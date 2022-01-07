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
        label 'Jenkins-Shared-DC2'
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
        timestamps ()
        disableConcurrentBuilds(abortPrevious: true)
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        string(name: "PULL_REQUEST_ID", defaultValue: "", description: "If you want to build a pull request, enter the pull request ID number here. Will override branch builds.")
        choice(name: "REGION", choices: ['useast', 'canadacentral'], description: "Azure region for the SQL solutions test")
    }
    environment {
        TEST_CONFIG = 'None'
    }
    stages {
        /* This stage is used in conjunction with APPROVED_AUTHORS list above
           to determine whether a build is authorized to run in CI or not.
           This stage is ran only for Jenkins multibranch pipeline builds
        */
        stage('Check access') {
            when {
                expression { params.PULL_REQUEST_ID == "" }
                expression { env.CHANGE_ID != null }
            }
            steps {
                sh """
                    while sudo lsof /var/lib/dpkg/lock-frontend | grep dpkg; do sleep 3; done
                    sudo apt-get -y --option Acquire::Retries=5 install jq
                """
                script {
                    PR_AUTHOR = sh(
                        script: "curl --silent https://api.github.com/repos/deislabs/mystikos/pulls/${env.CHANGE_ID} | jq --raw-output '.user | .login'",
                        returnStdout: true
                    ).trim()
                    if ( PR_AUTHOR == 'null' ) {
                        error("No pull request author found. This is an unexpected error. Does the pull request ID exist?")
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
        stage('Checkout') {
            when {
                // This is only necessary for manual PR builds or manual branch builds
                anyOf {
                    expression { params.PULL_REQUEST_ID != "" }
                    expression { params.BRANCH != "main" }
                }
            }
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
                            userRemoteConfigs: [[url: "https://github.com/${params.REPOSITORY}/mystikos"]]]
                        )
                    }
                    GIT_COMMIT_ID = sh(
                        returnStdout: true,
                        script: "git log --max-count=1 --pretty=format:'%H'"
                    ).trim()
                }
            }
        }
        stage('Determine committers') {
            steps {
                script {
                    if ( params.PULL_REQUEST_ID ) {
                        // This is the git ref for a manual PR build
                        SOURCE_BRANCH = "origin/pr/${params.PULL_REQUEST_ID}"
                    } else if ( params.BRANCH ) {
                        // This is the git ref for a manual branch build
                        SOURCE_BRANCH = "origin/${params.BRANCH}"
                    } else {
                        // This is the git ref in a Jenkins multibranch pipeline build
                        SOURCE_BRANCH = "origin/PR-${env.CHANGE_ID}"
                    }
                    dir("${WORKSPACE}") {
                        COMMITER_EMAILS = sh(
                            returnStdout: true,
                            script: "git log --pretty='%ae' origin/main..${SOURCE_BRANCH} | sort -u"
                        )
                    }
                }
            }
        }
        stage('Run PR Tests') {
            when {
                /* Jobs must meet any of the situations below in order to build:
                    1. Started manually
                    2. Started by a scheduler
                    2. Triggered by a GitHub pull request to main
                */
                anyOf {
                    triggeredBy 'UserIdCause'
                    triggeredBy 'TimerTrigger'
                    changeRequest target: 'main'
                }
            }
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
                                            string(name: "PULL_REQUEST_ID", value: params.PULL_REQUEST_ID),
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
                COMMITER_EMAILS.tokenize('\n').each {
                    emailext(
                        subject: "[Jenkins] [${currentBuild.currentResult}] [${env.JOB_NAME}] [#${env.BUILD_NUMBER}]",
                        body: "See build log for details: ${env.BUILD_URL}",
                        to: "${it}"
                    )
                }
            }
        }
    }
}
