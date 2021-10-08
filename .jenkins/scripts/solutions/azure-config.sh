sudo apt-get install -y azure-cli
az login --service-principal -u $SERVICE_PRINCIPAL_ID -p $SERVICE_PRINCIPAL_PASSWORD --tenant $TENANT_ID >> /dev/null
az account set -s $AZURE_SUBSCRIPTION_ID
az vm identity assign -g $JENKINS_RESOURCE_GROUP -n $(hostname) --identities $MYSTIKOS_MANAGED_ID >> /dev/null
az vm update -g $JENKINS_RESOURCE_GROUP -n $(hostname) --set identity.type='UserAssigned' >> /dev/null
