/* A Jenkins pipeline that will handle code coverage and nightly tests
*  These are the original pipelines:
*  https://github.com/deislabs/mystikos/blob/main/.azure_pipelines/ci-pipeline-code-coverage-nightly.yml
*/

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
        choice(name: "TEST_CONFIG", choices:['Nightly', 'Code Coverage'], description: "Test configuration to execute")
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
                    userRemoteConfigs: [[url: 'https://github.com/deislabs/mystikos']]])
                sh """
                   # Initialize dependencies repo
                   ${JENKINS_SCRIPTS}/global/init-config.sh

                   # Install global dependencies
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-install.sh
                   """
            }
        }
        stage('Init Code Coverage Config') {
            when {
                expression { params.TEST_CONFIG == 'Code Coverage' }
            }
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/code-coverage/init-install.sh
                   """
            }
        }
        stage('Build repo source') {
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/global/make-world.sh
                   """
            }
        }
        stage('Run all tests') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh "${JENKINS_SCRIPTS}/global/make-tests.sh"
                }
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
                    sh '''
                       ${JENKINS_SCRIPTS}/solutions/init-config.sh
                       ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                       ${JENKINS_SCRIPTS}/solutions/azure-config.sh
                       '''
                }
            }
        }
        stage('Run SQL Solution - USEAST') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    withCredentials([string(credentialsId: 'mystikos-sql-db-name-useast', variable: 'DB_NAME'),
                                     string(credentialsId: 'mystikos-sql-db-server-name-useast', variable: 'DB_SERVER_NAME'),
                                     string(credentialsId: 'mystikos-maa-url-useast', variable: 'MAA_URL'),
                                     string(credentialsId: 'mystikos-managed-identity-objectid', variable: 'DB_USERID'),
                                     string(credentialsId: 'mystikos-mhsm-client-secret', variable: 'CLIENT_SECRET'),
                                     string(credentialsId: 'mystikos-mhsm-client-id', variable: 'CLIENT_ID'),
                                     string(credentialsId: 'mystikos-mhsm-app-id', variable: 'APP_ID'),
                                     string(credentialsId: 'mystikos-mhsm-aad-url', variable: 'MHSM_AAD_URL'),
                                     string(credentialsId: 'mystikos-mhsm-ssr-pkey', variable: 'SSR_PKEY')
                    ]) {
                        sh "make tests -C ${WORKSPACE}/solutions"
                    }
                }
            }
        }
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
                           ${JENKINS_SCRIPTS}/global/run-azure-tests.sh \
                             ${WORKSPACE}/tests/azure-sdk-for-cpp  \
                             ${WORKSPACE}/solutions/dotnet_azure_sdk
                           """
                    }
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
        stage('Measure Code Coverage') {
            when {
                expression { params.TEST_CONFIG == 'Code Coverage' }
            }
            steps {
                sh """
                   ${MYST_SCRIPTS}/myst_cc
                   """
            }
        }
        stage('Report Code Coverage') {
            when {
                expression { params.TEST_CONFIG == 'Code Coverage' }
            }
            steps {
                script {
                    LCOV_DIR="mystikos-cc-${env.GIT_COMMIT}"
                }

                sh """
                   mkdir ${LCOV_DIR}
                   mv lcov* ${LCOV_DIR}
                   tar -zcvf ${LCOV_DIR}.tar.gz ${LCOV_DIR}
                   """

                azureUpload(
                    containerName: 'mystikos-code-coverage',
                    storageType: 'container',
                    uploadZips: true,
                    filesPath: "${LCOV_DIR}.tar.gz",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )
            }
        }
        stage('Cleanup') {
            steps {
                cleanWs()
            }
        }
    }
    post {
        always {
            emailext(
                subject: "Jenkins: ${env.JOB_NAME} [#${env.BUILD_NUMBER}] status is ${currentBuild.currentResult}",
                body: "See build log for details: ${env.BUILD_URL}", 
                recipientProviders: [[$class: 'DevelopersRecipientProvider'], [$class: 'RequesterRecipientProvider']]
            )
        }
    }
}
