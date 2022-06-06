/* A Jenkins pipeline that will handle code coverage and nightly tests
*  These are the original pipelines:
*  https://github.com/deislabs/mystikos/blob/main/.azure_pipelines/ci-pipeline-code-coverage-nightly.yml
*/

pipeline {
    agent {
        label 'Jenkins-Shared-DC2'
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
        timestamps ()
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs/mystikos")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        choice(name: "REGION", choices:['useast', 'canadacentral'], description: "Azure region for the SQL solutions test")
        string(name: "PULL_REQUEST_ID", defaultValue: "", description: "If you are building a pull request, enter the pull request ID number here. (ex. 789)")
    }
    environment {
        TEST_CONFIG = 'Code Coverage'
    }
    stages {
        stage('Run Code Coverage Tests') {
            matrix {
                axes {
                    axis {
                        name 'OS_VERSION'
                        values '18.04'
                    }
                    axis {
                        name 'TEST_PIPELINE'
                        values 'Unit', 'Solutions', 'DotNet', 'Azure-SDK'
                    }
                }
                stages {
                    stage("Matrix") {
                        steps {
                            script {
                                stage("${OS_VERSION} ${TEST_PIPELINE} (${TEST_CONFIG})") {
                                    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                        build job: "Standalone-Pipelines/${TEST_PIPELINE}-Tests-Pipeline",
                                        parameters: [
                                            string(name: "UBUNTU_VERSION", value: OS_VERSION),
                                            string(name: "REPOSITORY", value: params.REPOSITORY),
                                            string(name: "BRANCH", value: params.BRANCH),
                                            string(name: "PULL_REQUEST_ID", value: params.PULL_REQUEST_ID),
                                            string(name: "TEST_CONFIG", value: env.TEST_CONFIG),
                                            string(name: "REGION", value: params.REGION),
                                            string(name: "COMMIT_SYNC", value: params.GIT_COMMIT)
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // TODO: separate coverage reports for 18.04 and 20.04
        stage('Measure code coverage') {
            steps {
                build job: "Standalone-Pipelines/Measure-Code-Coverage",
                parameters: [
                    string(name: "REPOSITORY", value: REPOSITORY),
                    string(name: "BRANCH", value: BRANCH),
                    string(name: "COMMIT_ID", value: GIT_COMMIT[0..7])
                ]
            }
        }
    }
    post {
        always {
            build job: "Standalone-Pipelines/Report-Code-Coverage",
            parameters: [
                string(name: "REPOSITORY", value: REPOSITORY),
                string(name: "BRANCH", value: BRANCH),
                string(name: "COMMIT_ID", value: GIT_COMMIT[0..7]),
                string(name: "BUILD_URL", value: BUILD_URL)
            ]
        }
    }
}
