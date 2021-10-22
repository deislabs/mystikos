pipeline {
    agent {
        label 'ACC-1804-DC8'
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
    }
    parameters {
        string(name: "REPOSITORY")
        string(name: "BRANCH", description: "Branch to build")
        string(name: "TEST_CONFIG", description: "Test configuration to execute")
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
        stage('Pull build resource') {
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/global/make-repo-source.sh
                   """
            }
        }
        stage('Run all tests') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh """
                       ${JENKINS_SCRIPTS}/global/make-tests.sh
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
}
