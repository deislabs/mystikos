pipeline {
    agent {
        label 'Jenkins-Shared-DC2'
    }
    options {
        timeout(time: 720, unit: 'MINUTES')
        timestamps ()
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs/mystikos")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        string(name: "PULL_REQUEST_ID", defaultValue: "", description: "If you are building a pull request, enter the pull request ID number here. (ex. 789)")
        choice(name: "REGION", choices: ['useast', 'canadacentral'], description: "Azure region for the SQL solutions test")
        // Parameters for toggling optional tests.
        // Add to the below to if you are adding a new test that needs to be toggled. 
        booleanParam(name: "RUN_DOTNETP1", defaultValue: false, description: "Run .NET P1 tests?")
        booleanParam(name: "RUN_OPENMP_TESTSUITE", defaultValue: false, description: "Run OpenMP Test Suite?")
        // Parameters for OS/VM combinations
        booleanParam(name: "ICELAKE_VM", defaultValue: true, description: "Run tests on Ice Lake VMs?")
        booleanParam(name: "COFFEELAKE_VM", defaultValue: false, description: "Run tests on Coffee Lake VMs?")
    }
    environment {
        TEST_CONFIG = 'Nightly'
    }
    stages {
        stage('Parse params') {
            steps {
                script {
                    // This is used to skip any tests that were not enabled in build parameters.
                    // Add to the below to if you are adding a new test that needs to be toggled. 
                    IGNORE_TESTS = []
                    if ( ! params.RUN_DOTNETP1 ) { IGNORE_TESTS.add('DotNet-P1') }
                    if ( ! params.RUN_OPENMP_TESTSUITE ) { IGNORE_TESTS.add('OpenMP-Testsuite') }
                    // This is used to test on specific VM generations
                    IGNORE_VM_GENERATIONS = []
                    if ( ! params.ICELAKE_VM ) { IGNORE_VM_GENERATIONS.add('v3') }
                    if ( ! params.COFFEELAKE_VM ) { IGNORE_VM_GENERATIONS.add('v2') }
                }
            }
        }
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
                            userRemoteConfigs: [[
                                url: "https://github.com/${REPOSITORY}",
                                credentialsId: 'github-oeciteam-user-pat'
                            ]]
                        ])
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
                        values '20.04'
                    }
                    axis {
                        name 'TEST_PIPELINE'
                        // Append to the list below to add a new test
                        values 'Unit', 'Solutions', 'DotNet', 'DotNet-P1', 'Azure-SDK', 'PyTorch', 'OpenMP-Testsuite'
                    }
                    axis {
                        name 'VM_GENERATION'
                        values 'v3', 'v2'
                    }
                }
                excludes {
                    // Skip builds with Ubuntu 20.04 and v2
                    // But include 'Unit' and 'Solutions' tests
                    exclude {
                        axis {
                            name 'OS_VERSION'
                            values '20.04'
                        }
                        axis {
                            name 'VM_GENERATION'
                            values 'v2'
                        }
                        axis {
                            name 'TEST_PIPELINE'
                            values 'DotNet', 'DotNet-P1', 'Azure-SDK', 'PyTorch', 'OpenMP-Testsuite'
                        }
                    }
                }
                stages {
                    stage("Matrix") {
                        steps {
                            script {
                                stage("${TEST_PIPELINE} ${OS_VERSION} ACC-${VM_GENERATION} ${TEST_CONFIG}") {
                                    // Workaround for skipping optional tests as dynamic matrix axis values are not supported
                                    // https://issues.jenkins.io/browse/JENKINS-62127
                                    if ( IGNORE_TESTS.contains(TEST_PIPELINE) || IGNORE_VM_GENERATIONS.contains(VM_GENERATION) ) {
                                        catchError(buildResult: 'SUCCESS', stageResult: 'NOT_BUILT') {
                                            error "This test is skipped. You can enable this test in the build parameters."
                                        }
                                    } else {
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
                                                    string(name: "COMMIT_SYNC", value: GIT_COMMIT_ID),
                                                    string(name: "VM_GENERATION", value: VM_GENERATION)
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
