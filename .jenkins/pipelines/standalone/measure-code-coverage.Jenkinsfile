pipeline {
    agent {
        label 'ACC-1804-DC2'
    }
    options {
        timeout(time: 30, unit: 'MINUTES')
        timestamps ()
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs/mystikos")
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
        stage('Measure code coverage') {
            steps {
                script {
                    LCOV_DIR="mystikos-cc-${COMMIT_ID}"
                }

                azureDownload(
                    downloadType: 'container',
                    containerName: 'mystikos-code-coverage',
                    includeFilesPattern: "${LCOV_PREFIX}-*",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )

                sh """
                   ls -l

                   # Initialize dependencies repo
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-config.sh

                   # Install global dependencies
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-install.sh

                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/code-coverage/init-install.sh

                   lcov -a ${LCOV_PREFIX}-dotnet.info -a ${LCOV_PREFIX}-sdk.info -a ${LCOV_PREFIX}-solutions.info -a ${LCOV_PREFIX}-unit.info -o lcov.info
                   lcov --list lcov.info | tee -a code-coverage-report

                   rm -rf ${LCOV_DIR}
                   mkdir ${LCOV_DIR}
                   genhtml --branch-coverage -o lcov lcov.info || true

                   mv lcov* ${LCOV_DIR}
                   tar -zcvf ${LCOV_DIR}.tar.gz ${LCOV_DIR}
                   cp ${LCOV_DIR}/lcov.info ${LCOV_PREFIX}.info
                   """

                azureUpload(
                    containerName: 'mystikos-code-coverage',
                    storageType: 'container',
                    uploadZips: true,
                    filesPath: "${LCOV_DIR}.tar.gz",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )
                azureUpload(
                    containerName: 'mystikos-code-coverage',
                    storageType: 'container',
                    uploadZips: true,
                    filesPath: "${LCOV_PREFIX}.info",
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
