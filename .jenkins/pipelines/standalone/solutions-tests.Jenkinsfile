pipeline {
    agent {
        label UBUNTU_VERSION == '20.04' ? "ACC-${params.VM_GENERATION}-2004-DC4" : "ACC-${params.VM_GENERATION}-1804-DC4"
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
        timestamps ()
    }
    parameters {
        choice(name: "UBUNTU_VERSION", choices: ["18.04", "20.04"])
        string(name: "REPOSITORY", defaultValue: "deislabs")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        string(name: "PULL_REQUEST_ID", defaultValue: "", description: "If you are building a pull request, enter the pull request ID number here. (ex. 789)")
        choice(name: "REGION", choices: ['useast', 'canadacentral'], description: "Azure region for the SQL solution tests")
        choice(name: "TEST_CONFIG", choices: ['None', 'Nightly', 'Code Coverage'], description: "Test configuration to execute")
        choice(name: "VM_GENERATION", choices: ['v3', 'v2'], description: "v3 for Ice Lake VMs; v2 for Coffee Lake")
        string(name: "COMMIT_SYNC", defaultValue: "", description: "optional - used to sync outputs of parallel jobs")
        string(name: "PACKAGE_NAME", defaultValue: "", description: "optional - release package to install (do not include extension)")
        choice(name: "PACKAGE_EXTENSION", choices:['tar.gz', 'deb'], description: "Extension of package given in PACKAGE_NAME")
    }
    environment {
        MYST_SCRIPTS =      "${WORKSPACE}/scripts"
        JENKINS_SCRIPTS =   "${WORKSPACE}/.jenkins/scripts"
        MYST_NIGHTLY_TEST = "${TEST_CONFIG == 'Nightly' || TEST_CONFIG == 'Code Coverage' ? 1 : ''}"
        MYST_SKIP_PR_TEST = "${TEST_CONFIG == 'Nightly' || TEST_CONFIG == 'Code Coverage' ? '' : '1'}"
        MYST_ENABLE_GCOV =  "${TEST_CONFIG == 'Code Coverage' ? 1 : ''}"
        TEST_TYPE =         "solutions"
        LCOV_INFO =         "lcov-${GIT_COMMIT[0..7]}-${TEST_TYPE}.info"
        PACKAGE_INSTALL =   "${UBUNTU_VERSION == '20.04' ? 'Ubuntu-2004' : 'Ubuntu-1804'}_${PACKAGE_NAME}.${PACKAGE_EXTENSION}"
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
    }
    stages {
        stage("Cleanup files") {
            steps {
                sh "${JENKINS_SCRIPTS}/global/clean-temp.sh"
            }
        }
        stage("Checkout Pull Request") {
            when {
                expression { params.PULL_REQUEST_ID != "" }
            }
            steps {
                cleanWs()
                checkout([$class: 'GitSCM',
                    branches: [[name: "pr/${PULL_REQUEST_ID}"]],
                    extensions: [],
                    userRemoteConfigs: [[
                        url: 'https://github.com/deislabs/mystikos',
                        refspec: "+refs/pull/${PULL_REQUEST_ID}/merge:refs/remotes/origin/pr/${PULL_REQUEST_ID}"
                    ]]
                ])
            }
        }
        stage('Verify commit sync') {
            when {
                expression { params.COMMIT_SYNC != "" }
            }
            steps {
                // Check if the checked out commit is the same across all parallel builds
                script {
                    def GIT_COMMIT_ID = sh(
                        returnStdout: true,
                        script: "git log --max-count=1 --pretty=format:'%H'"
                    ).trim()
                    if ( GIT_COMMIT_ID != params.COMMIT_SYNC ) {
                        error("Checked out commit (${GIT_COMMIT_ID}) does not match commit from upstream job (${params.COMMIT_SYNC})")
                    } else {
                        println("Checked out commit (${GIT_COMMIT_ID}) matches upstream job (${params.COMMIT_SYNC}). Continuing with build.")
                    }
                }
            }
        }
        stage('Init Config') {
            steps {
                sh """
                   # Initialize dependencies repo
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-config.sh

                   # Install global dependencies
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-install.sh
                   """
            }
        }
        stage('Build repo source') {
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/solutions/make-build.sh
                   """
            }
        }
        stage("Install package") {
            environment {
                MYST_INSTALLED_BIN = "${ params.PACKAGE_EXTENSION == 'deb' ? '/opt/mystikos/bin' : '\${WORKSPACE}/mystikos/bin' }"
            }
            when {
                expression { params.PACKAGE_NAME != "" }
            }
            steps {
                azureDownload(
                    downloadType: 'container',
                    containerName: 'mystikosreleases',
                    includeFilesPattern: "${PACKAGE_INSTALL}",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )
                script {
                    if ( params.PACKAGE_EXTENSION == "deb" ) {
                        sh "sudo dpkg -i ${PACKAGE_INSTALL}"
                    } else {
                        sh """
                           rm -rf mystikos
                           tar xzf ${PACKAGE_INSTALL}
                           """
                    }

                    sh """
                       ln -sf ${MYST_INSTALLED_BIN}/myst-appbuilder ${WORKSPACE}/scripts/appbuilder
                       ln -sf ${MYST_INSTALLED_BIN}/myst ${WORKSPACE}/build/bin/myst
                       ln -sf ${MYST_INSTALLED_BIN}/myst-gdb ${WORKSPACE}/build/bin/myst-gdb

                       echo "Use installed binaries"
                       ls -l ${WORKSPACE}/build/bin/
                       ls -l ${WORKSPACE}/scripts
                       """
                }
            }
        }
        stage('Run Solutions Tests') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    withCredentials([string(credentialsId: "mystikos-sql-db-name-${REGION}", variable: 'DB_NAME'),
                                     string(credentialsId: "mystikos-sql-db-server-name-${REGION}", variable: 'DB_SERVER_NAME'),
                                     string(credentialsId: "mystikos-maa-url-${REGION}", variable: 'MAA_URL'),
                                     string(credentialsId: 'mystikos-sql-db-userid', variable: 'DB_USERID'),
                                     string(credentialsId: 'mystikos-sql-db-password', variable: 'DB_PASSWORD'),
                                     string(credentialsId: 'mystikos-mhsm-client-secret', variable: 'CLIENT_SECRET'),
                                     string(credentialsId: 'mystikos-mhsm-client-id', variable: 'CLIENT_ID'),
                                     string(credentialsId: 'mystikos-mhsm-app-id', variable: 'APP_ID'),
                                     string(credentialsId: 'mystikos-mhsm-aad-url', variable: 'MHSM_AAD_URL'),
                                     string(credentialsId: 'mystikos-mhsm-ssr-pkey', variable: 'SSR_PKEY')
                    ]) {
                        sh """
                           echo "MYST_NIGHTLY_TEST is set to \${MYST_NIGHTLY_TEST}"
                           echo "MYST_SKIP_PR_TEST is set to \${MYST_SKIP_PR_TEST}"
                           echo "Running in ${REGION}"
                           make solutions_tests
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
        stage('Upload code coverage') {
            when {
                expression { params.TEST_CONFIG == 'Code Coverage' }
            }
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/code-coverage/init-install.sh

                   ${MYST_SCRIPTS}/myst_cc
                   sed -i 's|SF:${WORKSPACE}|SF:|g' lcov.info

                   mv lcov.info ${LCOV_INFO}
                   """

                azureUpload(
                    containerName: 'mystikos-code-coverage',
                    storageType: 'container',
                    uploadZips: true,
                    filesPath: "${LCOV_INFO}",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )
            }
        }
        stage('Cleanup') {
            steps {
                cleanWs()
            }
        }
    }
    post {
        always {
            sh "df -h"
            sh "docker network ls"
            sh "docker ps -a"
            sh "docker images"
            sh "docker network inspect bridge"
            sh "docker system info"
            sh "docker system df"
        }
    }
}
