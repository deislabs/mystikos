/* A Jenkins pipeline that will handle pull request tests
*  The original pipelines:
*  https://github.com/deislabs/mystikos/blob/main/.azure_pipelines/ci-pipeline-makefile.yml
*/

APPROVED_AUTHORS = [
    'anakrish',
    'asvrada',
    'bodzhang',
    'CyanDevs',
    'Francis-Liu',
    'jxyang',
    'mikbras',
    'mingweishih',
    'RRathna',
    'paulcallen',
    'radhikaj',
    'rs--',
    'salsal97',
    'Sahakait',
    'vtikoo'
]

pipeline {
    agent {
        label 'ACC-1804-DC4'
    }
    options {
        timeout(time: 600, unit: 'MINUTES')
    }
    parameters {
        string(name: "SCRIPTS_ROOT", defaultValue: '${WORKSPACE}/.azure_pipelines/scripts', description: "Root directory")
        string(name: "BRANCH_NAME", defaultValue: "", description: "Option #1: If you want to build a branch instead of a pull request, enter the branch name here")
        string(name: "PULL_REQUEST_ID", defaultValue: "", description: "Option #2: If you want to build a pull request, enter the pull request ID number here. Will override branch builds.")
    }
    environment {
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
    }
    stages {
        stage('Check access') {
            when {
                // This step should only run for multibranch pipeline
                expression { params.PULL_REQUEST_ID == "" }
                expression { params.BRANCH_NAME == "" }
            }
            steps {
                sh """
                    while sudo lsof /var/lib/dpkg/lock-frontend | grep dpkg; do sleep 3; done
                    sudo apt-get -y --option Acquire::Retries=5 install jq
                """
                script {
                    if ( ! env.CHANGE_ID ) {
                        error("This does not seem to be a pull request from a multibranch pipeline. Ensure you have set either BRANCH_NAME or PULL_REQUEST_ID instead.")
                    }
                    PR_AUTHOR = sh(
                        script: "curl --silent https://api.github.com/repos/deislabs/mystikos/pulls/${env.CHANGE_ID} | jq --raw-output '.user | .login'",
                        returnStdout: true
                    ).trim()
                    if ( PR_AUTHOR == 'null' ) {
                        error("No pull request author found. This is an unexpected error")
                    }
                    if ( ! APPROVED_AUTHORS.contains(PR_AUTHOR) ) {
                        currentBuild.result = 'ABORTED'
                        error("Pull request author ${PR_AUTHOR} is not in the list of authorized users. Aborting build.")
                    } else {
                        println("Pull request author ${PR_AUTHOR} is whitelisted. Build will continue.")
                    }
                }
            }
        }
        stage('Build') {
            when {
                /* Jobs must meet any of the situations below in order to build:
                    1. Is started manually, or by a scheduler
                    2. Is testing a PR to main that contains more than just documentation changes
                */
                anyOf {
                    triggeredBy 'UserIdCause'
                    triggeredBy 'TimerTrigger'
                    allOf {
                        anyOf {
                            changeRequest target: 'main'
                            branch 'staging'
                            branch 'trying'
                        }
                        not {
                            anyOf {
                                changeset pattern: "doc/*"
                                changeset pattern: ".*(txt|md)\$", comparator: "REGEXP"
                            }
                        }
                    }
                }
            }
            stages {
                stage('Cleanup files') {
                    steps {
                        sh 'sudo rm -rf /tmp/myst*'
                        sh 'df'
                    }
                }
                stage('Cleanup') {
                    steps {
                        cleanWs()
                    }
                }
            }
        }
    }
}
