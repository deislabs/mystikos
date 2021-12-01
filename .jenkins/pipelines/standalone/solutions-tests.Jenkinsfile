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
        choice(name: "REGION", choices: ['useast', 'canadacentral'], description: "Azure region for the SQL solution tests")
        choice(name: "TEST_CONFIG", choices: ['None', 'Nightly', 'Code Coverage'], description: "Test configuration to execute")
        string(name: "COMMIT_SYNC", defaultValue: "", description: "optional - used to sync outputs of parallel jobs")
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
                           echo "Running samples"
                           sudo make install
                           export PATH="/opt/mystikos/bin:$PATH"
                           export MYSTIKOS_INSTALL_DIR="/opt/mystikos/"
                           make -j -C ${WORKSPACE}/samples
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
