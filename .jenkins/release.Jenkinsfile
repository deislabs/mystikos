/* A Jenkins pipeline that will run Mystikos release building, testing, and publishing
*  Originally from https://github.com/deislabs/mystikos/blob/main/.azure_pipelines/ci-pipeline-release.yml
*/

pipeline {
    agent {
        label 'ACC-1804-DC4'
    }
    options {
        timeout(time: 480, unit: 'MINUTES')
    }
    parameters {
        string(name: "BRANCH_NAME", defaultValue: "main", description: "Branch to build")
        string(name: "SCRIPTS_ROOT", defaultValue: '${WORKSPACE}/.azure_pipelines/scripts', description: "Root directory")
        choice(name: "MYST_NIGHTLY_TEST", choices:['1','0'], description: "Enable nightly test")
        string(name: "VERSION", defaultValue: "0.0.0")
        choice(name: "RELEASE_ARTIFACT", choices:['0','1'], description: "Publish Artifact?")
    }
    environment {
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
    }
    stages {
        stage("Cleanup files") {
            steps {
                sh 'sudo rm -rf /tmp/myst*'
                sh 'df'
            }
        }
        stage('Minimum init config') {
            steps {
                checkout([$class: 'GitSCM',
                    branches: [[name: BRANCH_NAME]],
                    extensions: [],
                    userRemoteConfigs: [[url: 'https://github.com/cyandevs/mystikos']]])
                sh """
                    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
                    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable"
                    sudo apt-get update
                    while sudo lsof /var/lib/dpkg/lock-frontend | grep dpkg; do sleep 3; done
                    sudo apt-get install build-essential python3-setuptools python3-pip llvm-7 libmbedtls-dev docker-ce azure-cli lldb-10 -y
                    sudo usermod -aG docker \${BUILD_USER}
                    docker system prune -a -f
                    df
                    """    
            }
        }
        stage("Generate release artifact") {
            steps {
                withEnv(["MYST_NIGHTLY_TEST=${params.MYST_NIGHTLY_TEST}",
                            "VERSION=${params.VERSION}"]) {
                    sh """
                        set -ex
                        echo "${params.VERSION}" > VERSION
                        echo "Creating release version ${params.VERSION}"
                        
                        # remove all untracked files and directories in the git repository
                        sudo rm -rf \$(git ls-files --others --directory)
                        make distclean
                        touch "mystikos-${params.VERSION}.tar.gz"
                        tar -czf "mystikos-${params.VERSION}.tar.gz" --exclude="mystikos-${params.VERSION}.tar.gz" .
                        
                        make -j MYST_RELEASE=1 world && make bindist
                    """
                }
            }
        }
        stage('Run all tests') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    withEnv(["MYST_NIGHTLY_TEST=${params.MYST_NIGHTLY_TEST}",
                                "VERSION=${params.VERSION}"]) {
                        sh """
                            rm -rf mystikos 
                            tar -xzf "mystikos-${params.VERSION}-x86_64.tar.gz"
                            export PATH="\${PATH}:\$(pwd)/mystikos/bin"
                            sed -i 's%BINDIR=\$(BUILDDIR)/bin/%BINDIR=\$(TOP)/mystikos/bin/%g' defs.mak
                            sed -i 's%SUBBINDIR=\$(BINDIR)/\$(SUBDIR)/%SUBBINDIR=\$(BUILDDIR)/bin/\$(SUBDIR)/%g' defs.mak
                            make -j tests ALLTESTS=1 VERBOSE=1
                        """
                    }
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
                        sh """
                            export PATH="\${PATH}:\$(pwd)/mystikos/bin"
                            make tests -C ${WORKSPACE}/solutions
                        """
                    }
                }
            }
        }
        stage('Run SQL solution - CACENTRAL') {
            when {
                expression { params.MYST_NIGHTLY_TEST == "1" }
            }
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    withCredentials([string(credentialsId: 'mystikos-sql-db-name-canadacentral', variable: 'DB_NAME'),
                                        string(credentialsId: 'mystikos-sql-db-server-name-canadacentral', variable: 'DB_SERVER_NAME'),
                                        string(credentialsId: 'mystikos-maa-url-canadacentral', variable: 'MAA_URL'),
                                        string(credentialsId: 'mystikos-managed-identity-objectid', variable: 'DB_USERID')]) {
                            sh """
                                make clean -C ${WORKSPACE}/solutions/sql_ae
                                make -C ${WORKSPACE}/solutions/sql_ae 
                                make run -C ${WORKSPACE}/solutions/sql_ae
                            """
                    }
                }
            }
        }
        stage('Run Azure SDK tests') {
            when {
                expression { params.MYST_NIGHTLY_TEST == "1" }
            }
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    withCredentials([string(credentialsId: 'Jenkins-ServicePrincipal-ID', variable: 'servicePrincipalId'),
                                        string(credentialsId: 'ACC-Prod-Tenant-ID', variable: 'tenantId'),
                                        string(credentialsId: 'Jenkins-ServicePrincipal-Password', variable: 'servicePrincipalKey'),
                                        string(credentialsId: 'mystikos-ci-keyvault-url', variable: 'AZURE_KEYVAULT_URL'),
                                        string(credentialsId: 'mystikos-ci-keyvault-url', variable: 'AZURE_TEST_KEYVAULT_URL'),
                                        string(credentialsId: 'ACC-Prod-Subscription-ID', variable: 'AZURE_SUBSCRIPTION_ID'),
                                        string(credentialsId: 'mystikos-storage-mystikosciacc-connectionstring', variable: 'STANDARD_STORAGE_CONNECTION_STRING')]) {
                        sh """
                            ${params.SCRIPTS_ROOT}/run-azure-tests.sh \
                                ${WORKSPACE}/tests/azure-sdk-for-cpp  \
                                ${WORKSPACE}/solutions/dotnet_azure_sdk \
                                ${WORKSPACE}/solutions/python_azure_sdk
                        """
                    }
                }
            }
        }
        stage('Run dotnet 5 P0 test suite') {
            when {
                expression { params.MYST_NIGHTLY_TEST == "1" }
            }
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh """
                        make tests -C ${WORKSPACE}/solutions/coreclr
                    """
                }
            }
        }
        stage('Run dotnet 5 P1 test suite') {
            when {
                expression { params.MYST_NIGHTLY_TEST == "1" }
            }
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh """
                        make tests -C ${WORKSPACE}/solutions/coreclr-p1
                    """
                }
            }
        }
        stage('Publish release binary') {
            when {
                expression { params.RELEASE_ARTIFACT == "1" }
                expression { currentBuild.result != 'FAILURE'}
            }
            steps {
                azureUpload(
                    containerName: 'mystikosreleases',
                    storageType: 'container',
                    uploadZips: true,
                    filesPath: "*mystikos-${params.VERSION}-x86_64.tar.gz",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )
            }
        }
        stage('Publish release source code') {
            when {
                expression { params.RELEASE_ARTIFACT == "1" }
                expression { currentBuild.result != 'FAILURE'}
            }
            steps {
                azureUpload(
                    containerName: 'mystikosreleases',
                    storageType: 'container',
                    uploadZips: true,
                    filesPath: "*mystikos-${params.VERSION}.tar.gz",
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
            emailext(
                subject: "Jenkins: ${env.JOB_NAME} [#${env.BUILD_NUMBER}] status is ${currentBuild.currentResult}",
                body: "See build log for details: ${env.BUILD_URL}", 
                recipientProviders: [[$class: 'RequesterRecipientProvider']]
            )
        }
    }
}
