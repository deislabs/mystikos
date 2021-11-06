/* A Jenkins pipeline that will handle code coverage and nightly tests
*  These are the original pipelines:
*  https://github.com/deislabs/mystikos/blob/main/.azure_pipelines/ci-pipeline-code-coverage-nightly.yml
*/

pipeline {
    agent {
        label 'ACC-1804-DC2'
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        choice(name: "REGION", choices:['useast', 'canadacentral'], description: "Azure region for SQL test")
    }
    stages {
        stage('Run Tests') {
            parallel {
                stage("Run Unit Tests") {
                    steps {
                    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                        build job: "Standalone-Pipelines/Unit-Test-Pipeline",
                        parameters: [
                            string(name: "REPOSITORY", value: REPOSITORY),
                            string(name: "BRANCH", value: BRANCH),
                            string(name: "TEST_CONFIG", value: "Code Coverage"),
                            string(name: "COMMIT_SYNC", value: GIT_COMMIT)
                        ]
                    }}
                }
                stage("Run SQL Tests") {
                    steps {
                    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                        build job: "Standalone-Pipelines/SQL-Test-Pipeline",
                        parameters: [
                            string(name: "REPOSITORY", value: REPOSITORY),
                            string(name: "BRANCH", value: BRANCH),
                            string(name: "TEST_CONFIG", value: "Code Coverage"),
                            string(name: "REGION", value: REGION),
                            string(name: "COMMIT_SYNC", value: GIT_COMMIT)
                        ]
                    }}
                }
                stage("Run DotNet Tests") {
                    steps {
                    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                        build job: "Standalone-Pipelines/DotNet-Test-Pipeline",
                        parameters: [
                            string(name: "REPOSITORY", value: REPOSITORY),
                            string(name: "BRANCH", value: BRANCH),
                            string(name: "TEST_CONFIG", value: "Code Coverage"),
                            string(name: "COMMIT_SYNC", value: GIT_COMMIT)
                        ]
                    }}
                }
                stage("Run Azure SDK Tests") {
                    steps {
                    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                        build job: "Standalone-Pipelines/Azure-SDK-Test-Pipeline",
                        parameters: [
                            string(name: "REPOSITORY", value: REPOSITORY),
                            string(name: "BRANCH", value: BRANCH),
                            string(name: "TEST_CONFIG", value: "Code Coverage"),
                            string(name: "COMMIT_SYNC", value: GIT_COMMIT)
                        ]
                    }}
                }
            }
        }
        stage('Measure and report code coverage') {
            steps {
                build job: "Standalone-Pipelines/Measure-Code-Coverage",
                parameters: [
                    string(name: "REPOSITORY", value: REPOSITORY),
                    string(name: "BRANCH", value: BRANCH),
                    string(name: "COMMIT_ID", value: GIT_COMMIT[0..7])
                ]
            }
        }
        stage('Cleanup') {
            steps {
                cleanWs()
            }
        }
    }
}
