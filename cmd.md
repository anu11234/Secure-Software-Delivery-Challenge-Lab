# Secure Software Delivery: Challenge Lab || **GSP521**

**Command:**

**Task1**
```bash
# Set environment variables automatically
export PROJECT_ID=$(gcloud config get-value project)
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")
export REGION="us-central1" # Replace with your lab's assigned region if different

# 1. Enable APIs
gcloud services enable \
  cloudkms.googleapis.com \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  container.googleapis.com \
  containerregistry.googleapis.com \
  artifactregistry.googleapis.com \
  containerscanning.googleapis.com \
  ondemandscanning.googleapis.com \
  binaryauthorization.googleapis.com

# 2. Download lab files
mkdir -p ~/sample-app && cd ~/sample-app
gcloud storage cp gs://spls/gsp521/* .

# 3. Create Artifact Registry Repositories
gcloud artifacts repositories create artifact-scanning-repo \
  --repository-format=docker \
  --location=$REGION \
  --description="Scanning Repository"

gcloud artifacts repositories create artifact-prod-repo \
  --repository-format=docker \
  --location=$REGION \
  --description="Production Repository"
```

**Task2**
```bash
# Add roles to Cloud Build Service Account
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com" \
  --role="roles/iam.serviceAccountUser"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com" \
  --role="roles/ondemandscanning.admin"
```

**Task3**
```bash
# 1. Create Attestor Note
cat <<EOF > note.json
{
  "attestation": {
    "hint": {
      "human_readable_name": "Container Vulnerabilities attestation authority"
    }
  }
}
EOF

curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  --data @note.json \
  "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes/?noteId=vulnerability_note"

# 2. Create Binary Authorization Attestor
gcloud container binauthz attestors create vulnerability-attestor \
  --attestation-authority-note=vulnerability_note \
  --attestation-authority-note-project=$PROJECT_ID

# 3. Set IAM policy on the note
cat <<EOF > note_policy.json
{
  "resource": "projects/${PROJECT_ID}/notes/vulnerability_note",
  "policy": {
    "bindings": [
      {
        "role": "roles/containeranalysis.notes.occurrences.viewer",
        "members": [
          "serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-binaryauthorization.iam.gserviceaccount.com"
        ]
      }
    ]
  }
}
EOF

curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  --data @note_policy.json \
  "https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/notes/vulnerability_note:setIamPolicy"

# 4. Create KMS Keyring and Key
gcloud kms keyrings create binauthz-keys --location=global

gcloud kms keys create lab-key \
  --location=global \
  --keyring=binauthz-keys \
  --purpose=asymmetric-signing \
  --default-algorithm=rsa-sign-pkcs1-2048-sha256

# 5. Link KMS Key to Attestor
gcloud container binauthz attestors public-keys add \
  --attestor=vulnerability-attestor \
  --keyversion-project=$PROJECT_ID \
  --keyversion-location=global \
  --keyversion-keyring=binauthz-keys \
  --keyversion-key=lab-key \
  --keyversion=1

# 6. Update Binary Authorization Policy
cat <<EOF > policy.yaml
defaultAdmissionRule:
  evaluationMode: REQUIRE_ATTESTATION
  enforcementMode: ENFORCE_BLOCK_AND_AUDIT_LOG
  requireAttestationsBy:
    - projects/${PROJECT_ID}/attestors/vulnerability-attestor
name: projects/${PROJECT_ID}/policy
EOF

gcloud container binauthz policy import policy.yaml
```

**Task4**
```bash
# 1. Grant IAM roles to Cloud Build & Compute Engine service accounts
for ROLE in roles/binaryauthorization.attestorsViewer roles/cloudkms.signerVerifier roles/containeranalysis.notes.attacher; do
  gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com" \
    --role="$ROLE"
done

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/cloudkms.signerVerifier"

# 2. Build custom attestation builder
git clone https://github.com/GoogleCloudPlatform/cloud-builders-community.git
cd cloud-builders-community/binauthz-attestation
gcloud builds submit . --config cloudbuild.yaml
cd ~/sample-app
rm -rf cloud-builders-community

# 3. Write fully expanded cloudbuild.yaml file
cat <<EOF > cloudbuild.yaml
steps:
- id: "build"
  name: 'gcr.io/cloud-builders/docker'
  args: ['build', '-t', '${REGION}-docker.pkg.dev/${PROJECT_ID}/artifact-scanning-repo/sample-image:latest', '.']
  waitFor: ['-']

- id: "push"
  name: 'gcr.io/cloud-builders/docker'
  args: ['push', '${REGION}-docker.pkg.dev/${PROJECT_ID}/artifact-scanning-repo/sample-image:latest']

- id: scan
  name: 'gcr.io/cloud-builders/gcloud'
  entrypoint: 'bash'
  args:
  - '-c'
  - |
    (gcloud artifacts docker images scan \
    ${REGION}-docker.pkg.dev/${PROJECT_ID}/artifact-scanning-repo/sample-image:latest \
    --location us \
    --format="value(response.scan)") > /workspace/scan_id.txt

- id: severity check
  name: 'gcr.io/cloud-builders/gcloud'
  entrypoint: 'bash'
  args:
  - '-c'
  - |
      gcloud artifacts docker images list-vulnerabilities \$(cat /workspace/scan_id.txt) \
      --format="value(vulnerability.effectiveSeverity)" | if grep -Fxq CRITICAL; \
      then echo "Failed vulnerability check for CRITICAL level" && exit 1; else echo \
      "No CRITICAL vulnerability found, congrats !" && exit 0; fi

- id: 'create-attestation'
  name: 'gcr.io/\${PROJECT_ID}/binauthz-attestation:latest'
  args:
    - '--artifact-url'
    - '${REGION}-docker.pkg.dev/${PROJECT_ID}/artifact-scanning-repo/sample-image:latest'
    - '--attestor'
    - 'vulnerability-attestor'
    - '--keyversion'
    - 'projects/${PROJECT_ID}/locations/global/keyRings/binauthz-keys/cryptoKeys/lab-key/cryptoKeyVersions/1'

- id: "push-to-prod"
  name: 'gcr.io/cloud-builders/docker'
  args: 
    - 'tag' 
    - '${REGION}-docker.pkg.dev/${PROJECT_ID}/artifact-scanning-repo/sample-image:latest'
    - '${REGION}-docker.pkg.dev/${PROJECT_ID}/artifact-prod-repo/sample-image:latest'

- id: "push-to-prod-final"
  name: 'gcr.io/cloud-builders/docker'
  args: ['push', '${REGION}-docker.pkg.dev/${PROJECT_ID}/artifact-prod-repo/sample-image:latest']

- id: 'deploy-to-cloud-run'
  name: 'gcr.io/cloud-builders/gcloud'
  entrypoint: 'bash'
  args:
  - '-c'
  - |
    gcloud run deploy auth-service --image=${REGION}-docker.pkg.dev/${PROJECT_ID}/artifact-prod-repo/sample-image:latest \
    --binary-authorization=default --region=${REGION} --allow-unauthenticated

images:
  - ${REGION}-docker.pkg.dev/${PROJECT_ID}/artifact-scanning-repo/sample-image:latest
EOF

# 4. Trigger Build (Expected to fail due to CRITICAL vulnerabilities)
gcloud builds submit . --config cloudbuild.yaml
```

**Task5**
```
# 1. Update Dockerfile base image
sed -i 's/FROM python:.*/FROM python:3.8-alpine/' Dockerfile

# 2. Update dependencies in requirements.txt (or requirements file present)
cat <<EOF > requirements.txt
Flask==3.0.3
Gunicorn==23.0.0
Werkzeug==3.0.4
EOF

# 3. Submit successful build
gcloud builds submit . --config cloudbuild.yaml

# 4. Grant unauthenticated access to Cloud Run service
gcloud beta run services add-iam-policy-binding --region=$REGION \
  --member=allUsers \
  --role=roles/run.invoker auth-service
```
