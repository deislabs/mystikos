pipeline {
    agent {
        label 'Jenkins-Shared-DC2'
    }
    options {
        timeout(time: 720, unit: 'MINUTES')
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs/mystikos")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        choice(name: "REGION", choices:['useast', 'canadacentral'], description: "Azure region for the SQL solutions test")
        string(name: "PACKAGE_NAME", description: "Release package to install (do not include extension)")
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
                        values 'Unit', 'Solutions', 'DotNet', 'DotNet-P1', 'Azure-SDK'
                    }
                    axis {
                        name 'TEST_PACKAGE'
                        values 'deb', 'tar.gz'
                    }
                }
                stages {
                    stage("Matrix") {
                        steps {
                            script {
                                stage("${OS_VERSION} ${TEST_PIPELINE} (${TEST_PACKAGE})") {
                                    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                        build job: "Standalone-Pipelines/${TEST_PIPELINE}-Tests-Pipeline",
                                        parameters: [
                                            string(name: "UBUNTU_VERSION", value: OS_VERSION),
                                            string(name: "REPOSITORY", value: params.REPOSITORY),
                                            string(name: "BRANCH", value: params.BRANCH),
                                            string(name: "TEST_CONFIG", value: env.TEST_CONFIG),
                                            string(name: "REGION", value: params.REGION),
                                            string(name: "COMMIT_SYNC", value: params.GIT_COMMIT),
                                            string(name: "PACKAGE_NAME", value: params.PACKAGE_NAME),
                                            string(name: "PACKAGE_EXTENSION", value: TEST_PACKAGE)
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
}
