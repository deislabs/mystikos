pipeline {
    agent {
        label 'ACC-1804-DC4'
    }
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        string(name: "COMMIT_ID", description: "Short commit ID used to archive build resoures")
    }
    environment {
        MYST_SCRIPTS =      "${WORKSPACE}/scripts"
        JENKINS_SCRIPTS =   "${WORKSPACE}/.jenkins/scripts"
        MYST_NIGHTLY_TEST = 1
        MYST_ENABLE_GCOV =  1
        LCOV_PREFIX =       "lcov-${COMMIT_ID}"
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
    }
    stages {
        stage('Measure and report code coverage') {
            steps {
                script {
                    LCOV_DIR="mystikos-cc-${COMMIT_ID}"
                }

                azureDownload(
                    downloadType: 'container',
                    containerName: 'mystikos-build-resources',
                    includeFilesPattern: "${LCOV_PREFIX}-*",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )

                sh """
                   ls -l

                   # Initialize dependencies repo
                   ${JENKINS_SCRIPTS}/global/init-config.sh

                   # Install global dependencies
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-install.sh

                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/code-coverage/init-install.sh

                   lcov -a ${LCOV_PREFIX}-dotnet.info -a ${LCOV_PREFIX}-sdk.info -a ${LCOV_PREFIX}-sql.info -a ${LCOV_PREFIX}-unit.info -o lcov.info
                   lcov --list lcov.info | tee -a code-coverage-report

                   ${MYST_SCRIPTS}/myst_cc_report

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
