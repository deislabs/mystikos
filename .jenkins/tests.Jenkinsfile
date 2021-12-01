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
                stage('Checkout') {
                    when {
                        anyOf {
                            expression { params.PULL_REQUEST_ID != "" }
                            expression { params.BRANCH_NAME != "" }
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
                                    branches: [[name: params.BRANCH_NAME]],
                                    extensions: [],
                                    userRemoteConfigs: [[url: 'https://github.com/deislabs/mystikos']]]
                                )
                            }
                        }
                    }
                }
                stage('Determine committers') {
                    steps {
                        script {
                            if ( params.PULL_REQUEST_ID ) {
                                SOURCE_BRANCH = "origin/pr/${params.PULL_REQUEST_ID}"
                            } else if ( params.BRANCH_NAME ) {
                                SOURCE_BRANCH = "origin/${BRANCH_NAME}"
                            } else {
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
                stage('Minimum init config') {
                    steps {
                        sh """
                        echo 'APT::Acquire::Retries "5";' | sudo tee /etc/apt/apt.conf.d/80-retries
                        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
                        sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable"
                        sudo apt-get update
                        while sudo lsof /var/lib/dpkg/lock-frontend | grep dpkg; do sleep 3; done
                        sudo apt-get install build-essential python3-setuptools python3-pip llvm-7 libmbedtls-dev docker-ce azure-cli lldb-10 -y
                        sudo usermod -aG docker \${BUILD_USER}
                        """    
                    }
                }
                stage('Build repo source') {
                    steps {
                        sh """
                            sudo rm -rf \$(git ls-files --others --directory)
                            docker system prune -a -f
                            make distclean
                        """
                        sh "make -j world"
                    }
                }
                stage('Run all tests') {
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            sh "make -j tests ALLTESTS=1 VERBOSE=1"
                        }
                    }
                }
                stage('Run solution tests') {
                    steps {
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            withCredentials([string(credentialsId: 'mystikos-sql-db-name-useast', variable: 'DB_NAME'),
                                            string(credentialsId: 'mystikos-sql-db-server-name-useast', variable: 'DB_SERVER_NAME'),
                                            string(credentialsId: 'mystikos-maa-url-useast', variable: 'MAA_URL'),
                                            string(credentialsId: 'mystikos-managed-identity-objectid', variable: 'DB_USERID')]) {
                                withEnv(["MYST_SKIP_PR_TEST=1"]) {
                                    sh """
                                       make tests -C ${WORKSPACE}/solutions
                                       echo "Running samples"
                                       sudo make install
                                       export PATH="/opt/mystikos/bin:$PATH"
                                       export MYSTIKOS_INSTALL_DIR="/opt/mystikos/"
                                       make -j -C ${WORKSPACE}/samples
                                       """
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
    }
    post {
        always {
            script {
                COMMITER_EMAILS.tokenize('\n').each {
                    emailext(
                        subject: "Jenkins: ${env.JOB_NAME} [#${env.BUILD_NUMBER}] status is ${currentBuild.currentResult}",
                        body: "See build log for details: ${env.BUILD_URL}",
                        to: "${it}"
                    )
                }
            }
        }
    }
}
