/* A Jenkins pipeline that will perform nightly tests
*  The original pipeline:
*  https://github.com/deislabs/mystikos/blob/main/.azure_pipelines/ci-pipeline-makefile-nightly.yml
*/

pipeline {
    agent {
        label 'ACC-1804-DC4'
    }
    options {
        timeout(time: 600, unit: 'MINUTES')
    }
    parameters {
        string(name: "BRANCH_NAME", defaultValue: "main", description: "Enter your pull request's source branch here (ex. main)")
        string(name: "REPOSITORY_NAME", defaultValue: "deislabs/mystikos", description: "Enter the name of the repository that your branch exists on (ex. deislabs/mystikos)")
        string(name: "PULL_REQUEST_ID", defaultValue: "", description: "If you are building a pull request, enter the pull request ID number here. (ex. 789)")
        string(name: "SCRIPTS_ROOT", defaultValue: '${WORKSPACE}/.azure_pipelines/scripts', description: "Root directory")
    }
    environment {
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
    }
    stages {
        stage("Build") {
            stages {
                stage("Cleanup files") {
                    steps {
                        sh 'sudo rm -rf /tmp/myst*'
                        sh 'df'
                    }
                }
                stage('Checkout') {
                    when {
                        anyOf {
                            expression { params.PULL_REQUEST_ID != "" }
                            expression { params.BRANCH_NAME != "" }
                        }
                    }
                    steps {
                        script {
                            if ( params.PULL_REQUEST_ID ) {
                                checkout([$class: 'GitSCM',
                                    branches: [[name: "pr/${PULL_REQUEST_ID}"]],
                                    extensions: [],
                                    userRemoteConfigs: [[
                                        url: 'https://github.com/deislabs/mystikos',
                                        refspec: "+refs/pull/${PULL_REQUEST_ID}/head:refs/remotes/origin/pr/${PULL_REQUEST_ID}"
                                    ]]
                                ])
                            } else {
                                checkout([$class: 'GitSCM',
                                    branches: [[name: params.BRANCH_NAME]],
                                    extensions: [],
                                    userRemoteConfigs: [[url: 'https://github.com/deislabs/mystikos']]]
                                )
                            }
                        }
                    }
                }
                stage('Minimum init config') {
                    steps {
                        sh """
                           curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
                           sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable"
                           sudo apt-get update
                           while sudo lsof /var/lib/dpkg/lock-frontend | grep dpkg; do sleep 3; done
                           sudo apt-get install build-essential python3-setuptools python3-pip llvm-7 libmbedtls-dev docker-ce azure-cli lldb-10 -y
                           sudo usermod -aG docker \${BUILD_USER}
                           """    
                    }
                }
                stage('Build repo source') {
                    steps {
                        withEnv(["MYST_NIGHTLY_TEST=1"]) {
                            sh """
                            sudo rm -rf \$(git ls-files --others --directory)
                            docker system prune -a -f
                            make distclean
                            """
                            sh "make -j world"
                        }
                    }
                }
                stage('Run all tests') {
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            withEnv(["MYST_NIGHTLY_TEST=1"]) {
                                sh "make -j tests ALLTESTS=1 VERBOSE=1"
                            }
                        }
                    }
                }
                /* This sets up the service principal and managed service identity used by the VM,
                *  which are required for the solution, SQL solution, and Azure SDK tests.
                */
                stage('Setup access') {
                    steps {
                        withCredentials([string(credentialsId: 'Jenkins-ServicePrincipal-ID', variable: 'SERVICE_PRINCIPAL_ID'),
                                         string(credentialsId: 'Jenkins-ServicePrincipal-Password', variable: 'SERVICE_PRINCIPAL_PASSWORD'),
                                         string(credentialsId: 'ACC-Prod-Tenant-ID', variable: 'TENANT_ID'),
                                         string(credentialsId: 'ACC-Prod-Subscription-ID', variable: 'AZURE_SUBSCRIPTION_ID'),
                                         string(credentialsId: 'oe-jenkins-dev-rg', variable: 'JENKINS_RESOURCE_GROUP'),
                                         string(credentialsId: 'mystikos-managed-identity', variable: "MYSTIKOS_MANAGED_ID")]) {
                            sh '''
                                echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ bionic main" | sudo tee /etc/apt/sources.list.d/azure-cli.list
                                wget https://packages.microsoft.com/keys/microsoft.asc
                                sudo apt-key add microsoft.asc
                                sudo apt-get update
                                while sudo lsof /var/lib/dpkg/lock-frontend | grep dpkg; do sleep 3; done
                                sudo apt-get install -y azure-cli
                                az login --service-principal -u ${SERVICE_PRINCIPAL_ID} -p ${SERVICE_PRINCIPAL_PASSWORD} --tenant ${TENANT_ID} >> /dev/null
                                az account set -s ${AZURE_SUBSCRIPTION_ID}
                                az vm identity assign -g ${JENKINS_RESOURCE_GROUP} -n \$(hostname) --identities ${MYSTIKOS_MANAGED_ID} >> /dev/null
                                az vm update -g ${JENKINS_RESOURCE_GROUP} -n \$(hostname) --set identity.type='UserAssigned' >> /dev/null
                            '''
                        }
                    }
                }
                stage('Run solution tests') {
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            withCredentials([string(credentialsId: 'mystikos-sql-db-name-useast', variable: 'DB_NAME'),
                                             string(credentialsId: 'mystikos-sql-db-server-name-useast', variable: 'DB_SERVER_NAME'),
                                             string(credentialsId: 'mystikos-maa-url-useast', variable: 'MAA_URL'),
                                             string(credentialsId: 'mystikos-maa-url-uscentral', variable: 'MAA_SHARED_URL'),
                                             string(credentialsId: 'mystikos-managed-identity-objectid', variable: 'DB_USERID'),
                                             string(credentialsId: 'mystikos-mhsm-client-secret', variable: 'CLIENT_SECRET'),
                                             string(credentialsId: 'mystikos-mhsm-client-id', variable: 'CLIENT_ID'),
                                             string(credentialsId: 'mystikos-mhsm-app-id', variable: 'APP_ID'),
                                             string(credentialsId: 'mystikos-mhsm-aad-url', variable: 'MHSM_AAD_URL'),
                                             string(credentialsId: 'mystikos-mhsm-ssr-pkey', variable: 'SSR_PKEY')
                            ]) {
                                withEnv(["MYST_NIGHTLY_TEST=1"]) {
                                    sh "make tests -C ${WORKSPACE}/solutions"
                                }
                            }
                        }
                    }
                }
                stage('Run SQL solution - CACENTRAL') {
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            withCredentials([string(credentialsId: 'mystikos-sql-db-name-canadacentral', variable: 'DB_NAME'),
                                             string(credentialsId: 'mystikos-sql-db-server-name-canadacentral', variable: 'DB_SERVER_NAME'),
                                             string(credentialsId: 'mystikos-maa-url-canadacentral', variable: 'MAA_URL'),
                                             string(credentialsId: 'mystikos-managed-identity-objectid', variable: 'DB_USERID')]) {
                                    sh """
                                        make clean -C ${WORKSPACE}/solutions/sql_ae
                                        make -C ${WORKSPACE}/solutions/sql_ae 
                                        make run -C ${WORKSPACE}/solutions/sql_ae
                                    """
                            }
                        }
                    }
                }
                /* Azure SDK tests require a service principal that has the following access on Azure:
                *    - contributor access to the subscription,
                *    - access policies for the Azure Key Vault. Specifically:
                *       - Keys: Get, List, Update, Create, Delete, Backup, Decrypt, Encrypt, Purge
                *       - Secrets: Get, List, Set, Delete, Backup, Purge
                *       - Certificates: Get, List, Update, Create, Delete, Backup, Purge
                */
                stage('Run Azure SDK tests') {
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            withCredentials([string(credentialsId: 'Jenkins-ServicePrincipal-ID', variable: 'servicePrincipalId'),
                                             string(credentialsId: 'ACC-Prod-Tenant-ID', variable: 'tenantId'),
                                             string(credentialsId: 'Jenkins-ServicePrincipal-Password', variable: 'servicePrincipalKey'),
                                             string(credentialsId: 'mystikos-ci-keyvault-url', variable: 'AZURE_KEYVAULT_URL'),
                                             string(credentialsId: 'mystikos-ci-keyvault-url', variable: 'AZURE_TEST_KEYVAULT_URL'),
                                             string(credentialsId: 'ACC-Prod-Subscription-ID', variable: 'AZURE_SUBSCRIPTION_ID'),
                                             string(credentialsId: 'mystikos-storage-mystikosciacc-connectionstring', variable: 'STANDARD_STORAGE_CONNECTION_STRING')]) {
                                sh """
                                    ${params.SCRIPTS_ROOT}/run-azure-tests.sh \
                                        ${WORKSPACE}/tests/azure-sdk-for-cpp  \
                                        ${WORKSPACE}/solutions/dotnet_azure_sdk \
                                        ${WORKSPACE}/solutions/python_azure_sdk
                                """
                            }
                        }
                    }
                }
                stage('Run dotnet 5 test suite') {
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
    }
}
