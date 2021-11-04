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
        choice(name: "TEST_CONFIG", choices:['None','Nightly', 'Code Coverage'], description: "Test configuration to execute")
        string(name: "COMMIT_SYNC", description: "optional - used to sync outputs of parallel jobs")
    }
    environment {
        MYST_SCRIPTS =      "${WORKSPACE}/scripts"
        JENKINS_SCRIPTS =   "${WORKSPACE}/.jenkins/scripts"
        MYST_NIGHTLY_TEST = "${TEST_CONFIG == 'Nightly' || TEST_CONFIG == 'Code Coverage' ? 1 : ''}"
        MYST_ENABLE_GCOV =  "${TEST_CONFIG == 'Code Coverage' ? 1 : ''}"
        TEST_TYPE =         "unit"
        LCOV_INFO =         "lcov-${GIT_COMMIT[0..7]}-${TEST_TYPE}.info"
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
    }
    stages {
        stage("Initialize Workspace") {
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
        stage("Run Unit Tests") {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh """
                       ${JENKINS_SCRIPTS}/global/make-tests.sh
                       """
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

                   ${MYST_SCRIPTS}/myst_cc_info
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
