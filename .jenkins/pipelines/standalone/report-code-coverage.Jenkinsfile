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
        string(name: "BUILD_URL", description: "URL of the upstream build")
    }
    environment {
        MYST_SCRIPTS =    "${WORKSPACE}/scripts"
        JENKINS_SCRIPTS = "${WORKSPACE}/.jenkins/scripts"
        LCOV_FILE =       "lcov-${COMMIT_ID}.info"
        BUILD_INFO =      "${BUILD_URL == '' ? 'N/A' : BUILD_URL}"
    }
    stages {
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
        stage('Download code coverage report') {
            steps {
                azureDownload(
                    downloadType: 'container',
                    containerName: 'mystikos-code-coverage',
                    includeFilesPattern: "${LCOV_FILE}",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )
            }
        }
        stage('Verify LCOV file') {
            when {
                not { expression { return fileExists(LCOV_FILE) } }
            }
            steps {
                script {
                    currentBuild.result = "FAILURE"
                    throw new Exception("LCOV file does not exist")
                }
            }
        }
        stage('Report code coverage') {
            steps {
                sh """
                   lcov --list ${LCOV_FILE} | tee code-coverage-summary

                   tail -n 1 code-coverage-summary | sed 's/|/ /g' | awk '{print "[Line: " \$2 ", Function: " \$4 "] Code Coverage Report"}' > email-subject

                   tail -n 1 code-coverage-summary | sed 's/|/ /g' | awk '{print "Summary:\\nLine coverage: " \$2 ", function coverage: " \$4 "\\n\\nBuild URL: ${BUILD_INFO}\\n\\nFull Report:"}' >> email-body
                   cat code-coverage-summary >> email-body
                   """

                script {
                    LCOV_REPORT = sh(
                        returnStdout: true,
                        script: "cat email-body"
                    )
                    EMAIL_SUBJECT = sh(
                        returnStdout: true,
                        script: "echo \"\$(cat email-subject) (\$(date '+%Y-%m-%d'))\""
                    )

                    build job:"Send-Email",
                    parameters: [
                        string(name: "REPOSITORY", value: REPOSITORY),
                        string(name: "BRANCH", value: BRANCH),
                        text(name: "EMAIL_SUBJECT", value: EMAIL_SUBJECT),
                        text(name: "EMAIL_BODY", value: LCOV_REPORT)
                    ]
                }
            }
        }
        stage('Cleanup') {
            steps {
                cleanWs()
            }
        }
    }
    post {
        failure {
            script {
                LCOV_REPORT = "Build URL: ${BUILD_INFO}"
                EMAIL_SUBJECT = sh(
                    returnStdout: true,
                    script: "echo \"[Failed] Code Coverage Report (\$(date '+%Y-%m-%d'))\""
                )

                build job:"Send-Email",
                parameters: [
                    string(name: "REPOSITORY", value: REPOSITORY),
                    string(name: "BRANCH", value: BRANCH),
                    text(name: "EMAIL_SUBJECT", value: EMAIL_SUBJECT),
                    text(name: "EMAIL_BODY", value: LCOV_REPORT)
                ]
            }
        }
    }
}
