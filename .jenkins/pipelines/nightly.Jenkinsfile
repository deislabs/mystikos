pipeline {
    agent {
        label 'Jenkins-Shared-DC2'
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        string(name: "PULL_REQUEST_ID", defaultValue: "", description: "If you are building a pull request, enter the pull request ID number here. (ex. 789)")
        choice(name: "REGION", choices: ['useast', 'canadacentral'], description: "Azure region for the SQL solutions test")
        booleanParam(name: "RUN_DOTNETP1", defaultValue: false, description: "Run .NET P1 tests?")
    }
    environment {
        TEST_CONFIG = 'Nightly'
    }
    stages {
        stage('Checkout') {
            when {
                anyOf {
                    expression { params.PULL_REQUEST_ID != "" }
                    expression { params.BRANCH != "" }
                }
            }
            steps {
                script {
                    if ( params.PULL_REQUEST_ID ) {
                        checkout([$class: 'GitSCM',
                            branches: [[name: "pr/${PULL_REQUEST_ID}"]],
                            extensions: [],
                            userRemoteConfigs: [[
                                url: 'https://github.com/deislabs/mystikos',
                                refspec: "+refs/pull/${PULL_REQUEST_ID}/merge:refs/remotes/origin/pr/${PULL_REQUEST_ID}"
                            ]]
                        ])
                    } else {
                        checkout([$class: 'GitSCM',
                            branches: [[name: params.BRANCH]],
                            extensions: [],
                            userRemoteConfigs: [[url: "https://github.com/${REPOSITORY}/mystikos"]]]
                        )
                    }
                    GIT_COMMIT_ID = sh(
                        returnStdout: true,
                        script: "git log --max-count=1 --pretty=format:'%H'"
                    ).trim()
                    if ( GIT_COMMIT_ID == "" ) {
                        error("Failed to fetch git commit ID")
                    }
                }
            }
        }
        stage('Run Nightly Tests') {
            matrix {
                axes {
                    axis {
                        name 'OS_VERSION'
                        values '18.04', '20.04'
                    }
                    axis {
                        name 'TEST_PIPELINE'
                        values 'Unit', 'Solutions', 'DotNet', 'DotNet-P1', 'Azure-SDK'
                    }
                }
                stages {
                    stage("Matrix") {
                        steps {
                            script {
                                // Workaround for skipping .NET P1 tests as dynamic matrix axis values are not supported
                                // https://issues.jenkins.io/browse/JENKINS-62127
                                if ( ! (TEST_PIPELINE == 'DotNet-P1' && ! params.RUN_DOTNETP1) ) {
                                    stage("${OS_VERSION} ${TEST_PIPELINE} (${TEST_CONFIG})") {
                                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                            build(
                                                job: "/Mystikos/Standalone-Pipelines/${TEST_PIPELINE}-Tests-Pipeline",
                                                parameters: [
                                                    string(name: "UBUNTU_VERSION", value: OS_VERSION),
                                                    string(name: "REPOSITORY", value: params.REPOSITORY),
                                                    string(name: "BRANCH", value: params.BRANCH),
                                                    string(name: "PULL_REQUEST_ID", value: params.PULL_REQUEST_ID),
                                                    string(name: "TEST_CONFIG", value: env.TEST_CONFIG),
                                                    string(name: "REGION", value: params.REGION),
                                                    string(name: "COMMIT_SYNC", value: GIT_COMMIT_ID)
                                                ]
                                            )
                                        }
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
            build(
                job: "/Mystikos/Standalone-Pipelines/Send-Email",
                parameters: [
                    string(name: "REPOSITORY", value: params.REPOSITORY),
                    string(name: "BRANCH", value: params.BRANCH),
                    string(name: "EMAIL_SUBJECT", value: "[Jenkins] [${currentBuild.currentResult}] [${env.JOB_NAME}] [#${env.BUILD_NUMBER}]"),
                    string(name: "EMAIL_BODY", value: "See build log for details: ${env.BUILD_URL}")
                ]
            )
        }
    }
}
