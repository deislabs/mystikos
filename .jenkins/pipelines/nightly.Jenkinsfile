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
        choice(name: "REGION", choices:['useast', 'canadacentral'], description: "Azure region for the SQL solutions test")
    }
    environment {
        TEST_CONFIG = 'Nightly'
    }
    stages {
        stage('Run Nightly Tests') {
            matrix {
                axes {
                    axis {
                        name 'OS_VERSION'
                        values '18.04', '20.04'
                    }
                    axis {
                        name 'TEST_PIPELINE'
                        values 'Unit', 'Solutions', 'DotNet', 'Azure-SDK'
                    }
                }
                stages {
                    stage("Run test pipeline") {
                        steps {
                            catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                build job: "Standalone-Pipelines/${TEST_PIPELINE}-Tests-Pipeline",
                                parameters: [
                                    string(name: "UBUNTU_VERSION", value: OS_VERSION),
                                    string(name: "REPOSITORY", value: REPOSITORY),
                                    string(name: "BRANCH", value: BRANCH),
                                    string(name: "TEST_CONFIG", value: TEST_CONFIG),
                                    string(name: "REGION", value: REGION),
                                    string(name: "COMMIT_SYNC", value: GIT_COMMIT)
                                ]
                            }
                        }
                    }
                }
            }
        }
    }
}
