pipeline {
    agent {
        label UBUNTU_VERSION == '20.04' ? 'ACC-2004-DC4' : 'ACC-1804-DC4'
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
    }
    parameters {
        choice(name: "UBUNTU_VERSION", choices:["18.04","20.04"])
        string(name: "REPOSITORY", defaultValue: "deislabs")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        choice(name: "REGION", choices:['useast', 'canadacentral'], description: "Azure region for the SQL solution tests")
        choice(name: "TEST_CONFIG", choices:['None','Nightly', 'Code Coverage'], description: "Test configuration to execute")
        string(name: "COMMIT_SYNC", description: "optional - used to sync outputs of parallel jobs")
    }
    environment {
        MYST_SCRIPTS =      "${WORKSPACE}/scripts"
        JENKINS_SCRIPTS =   "${WORKSPACE}/.jenkins/scripts"
        MYST_NIGHTLY_TEST = "${TEST_CONFIG == 'Nightly' || TEST_CONFIG == 'Code Coverage' ? 1 : ''}"
        MYST_ENABLE_GCOV =  "${TEST_CONFIG == 'Code Coverage' ? 1 : ''}"
        TEST_TYPE =         "solutions"
        LCOV_INFO =         "lcov-${GIT_COMMIT[0..7]}-${TEST_TYPE}.info"
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
    }
    stages {
        stage("Cleanup files") {
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/global/clean-temp.sh
                   """
            }
        }
        stage('Verify commit sync') {
            when { allOf {
                expression { params.COMMIT_SYNC != "" }
                expression { params.COMMIT_SYNC != GIT_COMMIT }
            }}
            steps {
                script {
                    currentBuild.result = 'ABORTED'
                    error("Aborting build: mismatched commit - commit($GIT_COMMIT), expected(${COMMIT_SYNC})")
                }
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
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-config.sh

                   # Install global dependencies
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-install.sh
                   """
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
                       ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                       ${JENKINS_SCRIPTS}/solutions/init-config.sh

                       ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                       ${JENKINS_SCRIPTS}/solutions/azure-config.sh
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
        stage('Run Solutions Tests') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    withCredentials([string(credentialsId: "mystikos-sql-db-name-${REGION}", variable: 'DB_NAME'),
                                     string(credentialsId: "mystikos-sql-db-server-name-${REGION}", variable: 'DB_SERVER_NAME'),
                                     string(credentialsId: "mystikos-maa-url-${REGION}", variable: 'MAA_URL'),
                                     string(credentialsId: 'mystikos-managed-identity-objectid', variable: 'DB_USERID'),
                                     string(credentialsId: 'mystikos-mhsm-client-secret', variable: 'CLIENT_SECRET'),
                                     string(credentialsId: 'mystikos-mhsm-client-id', variable: 'CLIENT_ID'),
                                     string(credentialsId: 'mystikos-mhsm-app-id', variable: 'APP_ID'),
                                     string(credentialsId: 'mystikos-mhsm-aad-url', variable: 'MHSM_AAD_URL'),
                                     string(credentialsId: 'mystikos-mhsm-ssr-pkey', variable: 'SSR_PKEY')
                    ]) {
                        sh """
                           echo "Running in ${REGION}"
                           make tests -C ${WORKSPACE}/solutions
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
                cleanWs()
            }
        }
    }
}
