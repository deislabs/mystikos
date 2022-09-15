#!/bin/bash

set -e
RESOURCE_GROUP=
CLUSTER_NAME=
HELLOWORLD_JOB=myst-helloworld
HELLOWORLD_YAML="myst-helloworld.yaml"
HELLOWORLD_JOB=myst-helloworld
HELLOWORLD_LABEL_KEY=app
HELLOWORLD_LABEL_VALUE=myst-helloworld

function main() {
    echo -e "\nValidate Helloworld"
    initialize_kubeconfig
    validate_myst-helloworld
    echo "Done"
}

function validate_myst-helloworld() {
    delete_all
    
    # Apply job
    kubectl apply -f $HELLOWORLD_YAML
    sleep 2
    kubectl get pods

    # display job logs
    JOB_POD=$(kubectl get pods -l $HELLOWORLD_LABEL_KEY=$HELLOWORLD_LABEL_VALUE -o 'jsonpath={..metadata.name}')
    kubectl logs $JOB_POD

    # wait for job completion
    kubectl wait --for=condition=Complete job/$HELLOWORLD_JOB --timeout=600s

    # display job logs
    JOB_POD=$(kubectl get pods -l $HELLOWORLD_LABEL_KEY=$HELLOWORLD_LABEL_VALUE -o 'jsonpath={..metadata.name}')
    kubectl logs $JOB_POD

    # delete_all
}

function delete_all()(
    echo -e "\nClean up all deployments"
    delete_resource job $HELLOWORLD_JOB
    wait_for_all_terminating_pods_to_complete
)

# Set kubectl to refer to the current clusters kubeconfig
function initialize_kubeconfig() {
    echo -e "\nDisplay cluster nodes created"
    az aks get-credentials --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME
    kubectl get nodes
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