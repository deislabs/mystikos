pipeline {
    agent {
        label 'Jenkins-Shared-DC2'
    }
    options {
        timeout(time: 30, unit: 'MINUTES')
        timestamps ()
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs/mystikos")
        string(name: "BRANCH", defaultValue: "main")
        string(name: "EMAIL_SUBJECT")
        string(name: "EMAIL_BODY")
    }
    stages {
        stage('Send email') {
            steps {
                withCredentials([string(credentialsId: 'mystikos-report', variable: 'MYSTIKOS_REPORT')]) {
                    script {
                        // Notify the build requestor only for manual builds
                        if ( params.REPOSITORY == 'deislabs' && params.BRANCH == 'main' ) {
                            emailext(
                                subject: "${EMAIL_SUBJECT}",
                                body: "${EMAIL_BODY}",
                                to: MYSTIKOS_REPORT
                            )
                        } else {
                            emailext(
                                subject: "${EMAIL_SUBJECT}",
                                body: "${EMAIL_BODY}",
                                recipientProviders: [[$class: 'RequesterRecipientProvider']]
                            )
                        }
                    }
                }
            }
        }
        stage('Cleanup') {
            steps {
                cleanWs()
            }
        }
    }
}
