pipeline {
    agent {
        label 'Jenkins-Shared-DC2'
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
        timestamps ()
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs/mystikos", description: "Required parameter. This should be the GitHub repository owner (e.g. your GitHub username).")
        string(name: "BRANCH", defaultValue: "main", description: "Required parameter. This should be your Github branch to build.")
        string(name: "PULL_REQUEST_ID", defaultValue: "", description: "Optional parameter. If you want to build a pull request, enter the pull request ID number here.")
        choice(name: "REGION", choices: ['useast', 'canadacentral'], description: "Choose an Azure region for the SQL solutions test")
    }
    environment {
        TEST_CONFIG = 'None'
    }
    stages {
        stage('Checkout') {
            steps {
                script {
                    if ( params.PULL_REQUEST_ID ) {
                        checkout([$class: 'GitSCM',
                            branches: [[name: "pr/${params.PULL_REQUEST_ID}"]],
                            extensions: [],
                            userRemoteConfigs: [[
                                url: 'https://github.com/deislabs/mystikos',
                                refspec: "+refs/pull/${params.PULL_REQUEST_ID}/merge:refs/remotes/origin/pr/${params.PULL_REQUEST_ID}"
                            ]]
                        ])
                    } else {
                        checkout([$class: 'GitSCM',
                            branches: [[name: params.BRANCH]],
                            extensions: [],
                            userRemoteConfigs: [[url: "https://github.com/${params.REPOSITORY}"]]]
                        )
                    }
                    GIT_COMMIT_ID = sh(
                        returnStdout: true,
                        script: "git log --max-count=1 --pretty=format:'%H'"
                    ).trim()
                    // Set pull request id for standalone builds
                    PULL_REQUEST_ID = params.PULL_REQUEST_ID
                }
            }
        }
        stage('Run PR Tests') {
            matrix {
                axes {
                    axis {
                        name 'OS_VERSION'
                        values '18.04', '20.04'
                    }
                    axis {
                        name 'TEST_PIPELINE'
                        values 'Unit', 'Solutions'
                    }
                }
                stages {
                    stage("Matrix") {
                        steps {
                            script {
                                stage("${OS_VERSION} ${TEST_PIPELINE} (${TEST_CONFIG})") {
                                    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                        build job: "/Mystikos/Standalone-Pipelines/${TEST_PIPELINE}-Tests-Pipeline",
                                        parameters: [
                                            string(name: "UBUNTU_VERSION", value: OS_VERSION),
                                            string(name: "REPOSITORY", value: params.REPOSITORY),
                                            string(name: "BRANCH", value: params.BRANCH),
                                            string(name: "PULL_REQUEST_ID", value: PULL_REQUEST_ID),
                                            string(name: "TEST_CONFIG", value: env.TEST_CONFIG),
                                            string(name: "REGION", value: params.REGION),
                                            string(name: "COMMIT_SYNC", value: params.GIT_COMMIT_ID),
                                            string(name: "VM_GENERATION", value: 'v3')
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    post {
        always {
            script {
                // Bug: Post stage does not show up on Blue Ocean here
                // https://issues.jenkins.io/browse/JENKINS-58850
                emailext(
                    subject: "[Jenkins] [${currentBuild.currentResult}] [${env.JOB_NAME}] [#${env.BUILD_NUMBER}]",
                    body: "See build log for details: ${env.BUILD_URL}",
                    recipientProviders: [requestor()]
                )
            }
        }
    }
}
