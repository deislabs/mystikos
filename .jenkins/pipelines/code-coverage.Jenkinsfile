/* A Jenkins pipeline that will handle code coverage and nightly tests
*  These are the original pipelines:
*  https://github.com/deislabs/mystikos/blob/main/.azure_pipelines/ci-pipeline-code-coverage-nightly.yml
*/

pipeline {
    agent {
        label 'ACC-v3-2004'
    }
    options {
        timeout(time: 600, unit: 'MINUTES')
        timestamps()
    }
    parameters {
        string(name: 'REPOSITORY', defaultValue: 'deislabs/mystikos')
        string(name: 'BRANCH', defaultValue: 'main', description: 'Branch to build')
        choice(name: 'REGION', choices:['useast', 'canadacentral'], description: 'Azure region for SQL solutions test')
        string(name: 'PULL_REQUEST_ID', defaultValue: '', description: 'If you are building a pull request, enter the pull request ID number here. (ex. 789)')
        string(name: 'PACKAGE_NAME', defaultValue: '', description: 'optional - release package to install (do not include extension)')
        choice(name: 'PACKAGE_EXTENSION', choices:['tar.gz', 'deb'], description: 'Extension of package given in PACKAGE_NAME')
    }
    environment {
        TEST_CONFIG = 'Code Coverage'
        UBUNTU_VERSION = '20.04'
        VM_GENERATION = 'v3'
        MYST_SCRIPTS =      "${WORKSPACE}/scripts"
        JENKINS_SCRIPTS =   "${WORKSPACE}/.jenkins/scripts"
        MYST_NIGHTLY_TEST = 1
        MYST_ENABLE_GCOV =  1
        LCOV_FILE =         "lcov-${GIT_COMMIT[0..7]}.info"
        LCOV_DIR = "mystikos-cc-${GIT_COMMIT[0..7]}"
        BUILD_INFO =      "${BUILD_URL == '' ? 'N/A' : BUILD_URL}"
        PACKAGE_INSTALL =   "${UBUNTU_VERSION == '20.04' ? 'Ubuntu-2004' : 'Ubuntu-1804'}_${PACKAGE_NAME}.${PACKAGE_EXTENSION}"
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
    }
    stages {
        stage('Cleanup files') {
            steps {
                sh "${JENKINS_SCRIPTS}/global/clean-temp.sh"
            }
        }
        stage('Checkout Pull Request') {
            when {
                expression { params.PULL_REQUEST_ID != '' }
            }
            steps {
                cleanWs()
                checkout([$class: 'GitSCM',
                    branches: [[name: "pr/${PULL_REQUEST_ID}"]],
                    extensions: [],
                    userRemoteConfigs: [[
                        url: 'https://github.com/deislabs/mystikos',
                        refspec: "+refs/pull/${PULL_REQUEST_ID}/merge:refs/remotes/origin/pr/${PULL_REQUEST_ID}"
                    ]]
                ])
            }
        }
        stage('Init Config') {
            steps {
                sh """
                   # Initialize dependencies repo
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-config.sh

                   # Install global dependencies
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-install.sh
                   """
            }
        }
        stage('Setup AZ CLI') {
            steps {
                withCredentials([string(credentialsId: 'Jenkins-ServicePrincipal-ID', variable: 'SERVICE_PRINCIPAL_ID'),
                                    string(credentialsId: 'Jenkins-ServicePrincipal-Password', variable: 'SERVICE_PRINCIPAL_PASSWORD'),
                                    string(credentialsId: 'ACC-Prod-Tenant-ID', variable: 'TENANT_ID'),
                                    string(credentialsId: 'ACC-Prod-Subscription-ID', variable: 'AZURE_SUBSCRIPTION_ID')]) {
                    sh """
                        ${JENKINS_SCRIPTS}/azure-sdk/install-azure-cli.sh
                        ${JENKINS_SCRIPTS}/azure-sdk/login-azure-cli.sh
                    """
                                    }
            }
        }
        stage('Build repo source') {
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/global/make-world.sh
                   """
            }
        }
        stage('Run Unit Tests') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh "${JENKINS_SCRIPTS}/global/make-tests.sh"
                    sh "${JENKINS_SCRIPTS}/global/clean-temp.sh"
                }
            }
        }
        stage('Run Solutions Tests') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    withCredentials([string(credentialsId: "mystikos-sql-db-name-${REGION}", variable: 'DB_NAME'),
                                     string(credentialsId: "mystikos-sql-db-server-name-${REGION}", variable: 'DB_SERVER_NAME'),
                                     string(credentialsId: "mystikos-maa-url-${REGION}", variable: 'MAA_URL'),
                                     string(credentialsId: 'mystikos-sql-db-userid', variable: 'DB_USERID'),
                                     string(credentialsId: 'mystikos-sql-db-password', variable: 'DB_PASSWORD'),
                                     string(credentialsId: 'mystikos-mhsm-client-secret', variable: 'CLIENT_SECRET'),
                                     string(credentialsId: 'mystikos-mhsm-client-id', variable: 'CLIENT_ID'),
                                     string(credentialsId: 'mystikos-mhsm-app-id', variable: 'APP_ID'),
                                     string(credentialsId: 'mystikos-mhsm-aad-url', variable: 'MHSM_AAD_URL'),
                                     string(credentialsId: 'mystikos-mhsm-ssr-pkey', variable: 'SSR_PKEY')
                    ]) {
                        sh """
                           echo "MYST_NIGHTLY_TEST is set to \${MYST_NIGHTLY_TEST}"
                           echo "MYST_SKIP_PR_TEST is set to \${MYST_SKIP_PR_TEST}"
                           echo "Running in ${REGION}"
                           make solutions_tests
                           echo "Running samples"
                           sudo make install
                           export PATH="/opt/mystikos/bin:$PATH"
                           export MYSTIKOS_INSTALL_DIR="/opt/mystikos/"
                           make -j -C ${WORKSPACE}/samples
                           """
                        sh "${JENKINS_SCRIPTS}/global/clean-temp.sh"
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
                             ${WORKSPACE}/solutions/dotnet_azure_sdk \
                             ${WORKSPACE}/solutions/python_azure_sdk
                           """
                        sh "${JENKINS_SCRIPTS}/global/clean-temp.sh"
                                     }
                }
            }
        }
        stage('Run DotNet 5.0 p0 Alpine Test Suite') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh "make tests -C ${WORKSPACE}/tests/coreclr/p0-net5.0-alpine"
                    sh "${JENKINS_SCRIPTS}/global/clean-temp.sh"
                }
            }
        }
        stage('Run DotNet 6.0 p0 Ubuntu Test Suite') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh "make tests -C ${WORKSPACE}/tests/coreclr/p0-net6.0-ubuntu"
                    sh "${JENKINS_SCRIPTS}/global/clean-temp.sh"
                }
            }
        }
        stage('Upload code coverage') {
            steps {
                sh """
                   set -ex

                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/code-coverage/init-install.sh

                   ${MYST_SCRIPTS}/myst_cc
                   sed -i 's|SF:${WORKSPACE}|SF:|g' lcov.info
                   cp lcov.info ${LCOV_FILE}

                   rm -rf ${LCOV_DIR}
                   mkdir ${LCOV_DIR}
                   mkdir html_lcov

                   cp -r lcov/* html_lcov/
                   mv lcov* ${LCOV_DIR}
                   tar -zcvf ${LCOV_DIR}.tar.gz ${LCOV_DIR}
                   """

                publishHTML(target: [
                    allowMissing: false,
                    alwaysLinkToLastBuild: false,
                    keepAll: true,
                    reportDir: 'html_lcov',
                    reportFiles: 'index.html',
                    reportName: 'Code Coverage Report',
                    reportTitles: ''])

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
            script {
                def EMAIL_SUBJECT = "Code Coverage Report " + sh(script: 'date +%Y-%m-%d', returnStdout: true).trim() + " ${currentBuild.currentResult}"
                def EMAIL_BODY = "Build URL: ${BUILD_INFO}"

                build job: '/Mystikos/Standalone-Pipelines/Send-Email',
                parameters: [
                    string(name: 'REPOSITORY', value: REPOSITORY),
                    string(name: 'BRANCH', value: BRANCH),
                    text(name: 'EMAIL_SUBJECT', value: EMAIL_SUBJECT),
                    text(name: 'EMAIL_BODY', value: EMAIL_BODY)
                ]

                sh 'df -h'
                sh 'docker network ls'
                sh 'docker ps -a'
                sh 'docker images'
                sh 'docker network inspect bridge'
                sh 'docker system info'
                sh 'docker system df'
            }
        }
    }
}
