pipeline {
    agent {
        label UBUNTU_VERSION == '20.04' ? 'ACC-2004-DC4' : 'ACC-1804-DC4'
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
    }
    parameters {
        choice(name: "UBUNTU_VERSION", choices: ["18.04", "20.04"])
        string(name: "REPOSITORY", defaultValue: "deislabs")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        string(name: "PULL_REQUEST_ID", defaultValue: "", description: "If you are building a pull request, enter the pull request ID number here. (ex. 789)")
        choice(name: "TEST_CONFIG", choices: ['None', 'Nightly', 'Code Coverage'], description: "Test configuration to execute")
        string(name: "COMMIT_SYNC", defaultValue: "", description: "optional - used to sync outputs of parallel jobs")
    }
    environment {
        MYST_SCRIPTS =      "${WORKSPACE}/scripts"
        JENKINS_SCRIPTS =   "${WORKSPACE}/.jenkins/scripts"
        MYST_NIGHTLY_TEST = "${TEST_CONFIG == 'Nightly' || TEST_CONFIG == 'Code Coverage' ? 1 : ''}"
        MYST_ENABLE_GCOV =  "${TEST_CONFIG == 'Code Coverage' ? 1 : ''}"
        TEST_TYPE =         "sdk"
        LCOV_INFO =         "lcov-${GIT_COMMIT[0..7]}-${TEST_TYPE}.info"
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
    }
    stages {
        stage("Cleanup files") {
            steps {
                sh "${JENKINS_SCRIPTS}/global/clean-temp.sh"
            }
        }
        stage("Checkout Pull Request") {
            when {
                expression { params.PULL_REQUEST_ID != "" }
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
        stage('Verify commit sync') {
            when {
                expression { params.COMMIT_SYNC != "" }
            }
            steps {
                // Check if the checked out commit is the same across all parallel builds
                script {
                    def GIT_COMMIT_ID = sh(
                        returnStdout: true,
                        script: "git log --max-count=1 --pretty=format:'%H'"
                    ).trim()
                    if ( GIT_COMMIT_ID != params.COMMIT_SYNC ) {
                        error("Checked out commit (${GIT_COMMIT_ID}) does not match commit from upstream job (${params.COMMIT_SYNC})")
                    } else {
                        println("Checked out commit (${GIT_COMMIT_ID}) matches upstream job (${params.COMMIT_SYNC}). Continuing with build.")
                    }
                }
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
        stage('Upload code coverage') {
            when {
                expression { params.TEST_CONFIG == 'Code Coverage' }
            }
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/code-coverage/init-install.sh

                   ${MYST_SCRIPTS}/myst_cc
                   sed -i 's|SF:${WORKSPACE}|SF:|g' lcov.info

                   mv lcov.info ${LCOV_INFO}
                   """

                azureUpload(
                    containerName: 'mystikos-code-coverage',
                    storageType: 'container',
                    uploadZips: true,
                    filesPath: "${LCOV_INFO}",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )
            }
        }
        stage('Cleanup') {
            steps {
                sh "${JENKINS_SCRIPTS}/azure-sdk/logout-azure-cli.sh"
                cleanWs()
            }
        }
    }
}
