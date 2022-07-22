#!/bin/bash

set -e
RESOURCE_GROUP=
CLUSTER_NAME=
CONFML_SERVER_SERVICE=confml-service
CONFML_SERVER_DEPLOYMENT=confml-server-demo
CONFML_SERVER_YAML="confml_server.yaml"
CONFML_CLIENT_YAML="confml_client.yaml"
CONFML_SERVER_SERVICE_LABEL_KEY=app
CONFML_SERVER_SERVICE_LABEL_VALUE=confml-server
CONFML_CLIENT_JOB=confml-client
CONFML_CLIENT_LABEL_KEY=app
CONFML_CLIENT_LABEL_VALUE=confml-client

function main() {
    echo -e "\nValidate Confidential ML"
    initialize_kubeconfig
    validate_confml
    echo "Done"
}

function validate_confml() {

    delete_all
    
    function deploy_server()(

        # Apply server service & deployment
        kubectl apply -f $CONFML_SERVER_YAML
        sleep 10
        kubectl get pods
        
        # verify pod is ready
        SERVER_POD=$(kubectl get pods -l $CONFML_SERVER_SERVICE_LABEL_KEY=$CONFML_SERVER_SERVICE_LABEL_VALUE -o 'jsonpath={..metadata.name}')
        kubectl get pods
        kubectl get nodes
        kubectl wait --for=condition=Ready pod/$SERVER_POD --timeout=600s
        kubectl logs $SERVER_POD

        sleep 15

    )
    deploy_server

    # remove extra time in deploy_client
    kubectl get svc | grep $CONFML_SERVER_SERVICE
    echo -e "\nWaiting for server IP to be assigned" && wait_for_external_ip

    function deploy_client()(

        IMAGE=$1

        delete_resource job $CONFML_CLIENT_JOB
        wait_for_all_terminating_pods_to_complete

        # Display service details
        kubectl get svc | grep $CONFML_SERVER_SERVICE
        wait_for_external_ip

        # Apply client job
        cat $CONFML_CLIENT_YAML | sed -e "s@IP_ADDRESS@$IP_ADDRESS@" -e "s@IMAGE_NAME@$IMAGE@" | kubectl create -f -
        sleep 10
        kubectl get pods
        CLIENT_POD=$(kubectl get pods -l $CONFML_CLIENT_LABEL_KEY=$CONFML_CLIENT_LABEL_VALUE -o 'jsonpath={..metadata.name}')
        kubectl describe job/$CONFML_CLIENT_JOB
        kubectl logs $CLIENT_POD

        kubectl wait --for=condition=Complete job/$CONFML_CLIENT_JOB --timeout=600s
        kubectl logs $CLIENT_POD
        echo "Icelake $(kubectl logs $CLIENT_POD | grep real | awk '{ print $2 }') $IMAGE" >> results.txt 

    )
    
    deploy_client automotive.jpg
    deploy_client dog.jpg
    deploy_client strawberries.jpg

    deploy_client dog.jpg.encrypted
    deploy_client automotive.jpg.encrypted
    deploy_client strawberries.jpg.encrypted

    delete_all
}

function delete_all()(
    echo -e "\nClean up all deployments"
    delete_resource job $CONFML_CLIENT_JOB
    delete_resource deployment $CONFML_SERVER_DEPLOYMENT
    delete_resource service $CONFML_SERVER_SERVICE
    wait_for_all_terminating_pods_to_complete
)

# Set kubectl to refer to the current clusters kubeconfig
function initialize_kubeconfig() {
    echo -e "\nDisplay cluster nodes created"
    az aks get-credentials --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME
    kubectl get nodes
}

# populates the IP_ADDRESS field
function get_external_ip() {
    IP_ADDRESS=$(kubectl get svc $CONFML_SERVER_SERVICE --template="{{range .status.loadBalancer.ingress}}{{.ip}}{{end}}")
}

# populates the IP_ADDRESS field
function wait_for_external_ip() {
    IP_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
    TIME_WAITED=0
    TIMEOUT=300
    POLL=5
    IP_ADDRESS=''
    get_external_ip
    while [[ ! $IP_ADDRESS =~ $IP_REGEX ]] # poll if regex match is false
    do
        sleep $POLL
        TIME_WAITED=$(($TIME_WAITED+$POLL))
        if [[ $TIME_WAITED = 300 ]]
        then
            echo "External IP Timed out" 1>&2
            exit 1
        fi
        get_external_ip
    done
    echo -e "\nExternal IP Found! IP_ADDRESS=$IP_ADDRESS"
}

# This function waits for all terminating pods to be completely terminated
function wait_for_all_terminating_pods_to_complete() {
    while : ; do
        terminating=$(kubectl get pods | awk '/Terminating/' | wc -l)
        [  $terminating -gt 0 ] || break
        sleep 10
        echo "Waiting...there are some terminating pods."
    done
}

# $1=RESOURCE_TYPE $2=RESOURCE_NAME $3=NAMESPACE
function delete_resource() {
    RESOURCE_TYPE=${1:-"default"}
    RESOURCE_NAME=${2:-"default"}
    NAMESPACE=${3:-"default"}

    EXISTS=$(kubectl get $RESOURCE_TYPE $RESOURCE_NAME -n $NAMESPACE | awk {'print $1'} | tail -1)
    if [[ $EXISTS != "" ]]; then
        echo "deleting $RESOURCE_NAME"
        kubectl delete $RESOURCE_TYPE $RESOURCE_NAME -n $NAMESPACE
    fi
}

main "$@"; exit