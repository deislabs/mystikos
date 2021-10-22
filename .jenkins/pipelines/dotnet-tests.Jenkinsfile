pipeline {
    agent {
        label 'ACC-1804-DC4'
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        string(name: "BUILD_RESOURCES", description: "prebuilt resources stash from parent node")
    }
    environment {
        MYST_SCRIPTS =    "${WORKSPACE}/scripts"
        JENKINS_SCRIPTS = "${WORKSPACE}/.jenkins/scripts"
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
        MYST_NIGHTLY_TEST = 1
        MYST_ENABLE_GCOV = 1
    }
    stages {
        stage("Cleanup files") {
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/global/clean-temp.sh
                   """
            }
        }
        stage('Init Config') {
            steps {
                checkout([$class: 'GitSCM',
                    branches: [[name: BRANCH]],
                    extensions: [],
                    userRemoteConfigs: [[url: 'https://github.com/${REPOSITORY}/mystikos']]])
                sh """
                   # Initialize dependencies repo
                   ${JENKINS_SCRIPTS}/global/init-config.sh

                   # Install global dependencies
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-install.sh
                   """
            }
        }
        stage('Pull build resource') {
            steps {
                azureDownload(
                    downloadType: 'container',
                    containerName: 'mystikos-build-resources',
                    includeFilesPattern: "${BUILD_RESOURCES}",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )
                sh "tar -xzf ${BUILD_RESOURCES}"
            }
        } 
        stage('Setup Solutions Access') {
            steps {
                withCredentials([string(credentialsId: 'Jenkins-ServicePrincipal-ID', variable: 'SERVICE_PRINCIPAL_ID'),
                                 string(credentialsId: 'Jenkins-ServicePrincipal-Password', variable: 'SERVICE_PRINCIPAL_PASSWORD'),
                                 string(credentialsId: 'ACC-Prod-Tenant-ID', variable: 'TENANT_ID'),
                                 string(credentialsId: 'ACC-Prod-Subscription-ID', variable: 'AZURE_SUBSCRIPTION_ID'),
                                 string(credentialsId: 'oe-jenkins-dev-rg', variable: 'JENKINS_RESOURCE_GROUP'),
                                 string(credentialsId: 'mystikos-managed-identity', variable: "MYSTIKOS_MANAGED_ID")]) {
                    sh """
                       ${JENKINS_SCRIPTS}/solutions/init-config.sh
                       ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                       ${JENKINS_SCRIPTS}/solutions/azure-config.sh
                       """
                }
            }
        }
        stage('Run DotNet 5 Test Suite') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh """
                       make tests -C ${WORKSPACE}/solutions/coreclr
                       """
                }
            }
        }
        stage('Cleanup') {
            steps {
                cleanWs()
            }
        }
    }
}
