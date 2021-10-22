/* A Jenkins pipeline that will handle code coverage and nightly tests
*  These are the original pipelines:
*  https://github.com/deislabs/mystikos/blob/main/.azure_pipelines/ci-pipeline-code-coverage-nightly.yml
*/

pipeline {
    agent {
        label 'ACC-1804-DC8-build-machine'
    }
    options {
        timeout(time: 300, unit: 'MINUTES')
    }
    parameters {
        string(name: "REPOSITORY", defaultValue: "deislabs")
        string(name: "BRANCH", defaultValue: "main", description: "Branch to build")
        choice(name: "TEST_CONFIG", choices:['Nightly', 'Code Coverage'], description: "Test configuration to execute")
        choice(name: "REGION", choices:['useast', 'canadacentral'], description: "Azure region for SQL test")
    }
    environment {
        MYST_SCRIPTS =      "${WORKSPACE}/scripts"
        JENKINS_SCRIPTS =   "${WORKSPACE}/.jenkins/scripts"
        MYST_NIGHTLY_TEST = 1
        MYST_ENABLE_GCOV =  1
        BUILD_RESOURCES =   "build-resources-${GIT_COMMIT[0..7]}"
        BUILD_USER = sh(
            returnStdout: true,
            script: 'echo \${USER}'
        )
    }
    stages {
        stage("Initialize Workspace") {
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/global/clean-temp.sh
                   """
                azureDownload(
                    downloadType: 'container',
                    containerName: 'mystikos-build-resources',
                    includeFilesPattern: "${BUILD_RESOURCES}",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )
            }
        }
        stage('Init Config') {
            when {
                not { expression { return fileExists("${BUILD_RESOURCES}") }}
            }
            steps {
                checkout([$class: 'GitSCM',
                    branches: [[name: BRANCH]],
                    extensions: [],
                    userRemoteConfigs: [[url: 'https://github.com/${REPOSITORY}/mystikos']]])
                sh """
                   # Initialize dependencies repo
                   ${JENKINS_SCRIPTS}/global/init-config.sh

                   # Install global dependencies
                   ${JENKINS_SCRIPTS}/global/wait-dpkg.sh
                   ${JENKINS_SCRIPTS}/global/init-install.sh
                   """
            }
        }
        stage('Build repo source') {
            when {
                not { expression { return fileExists("${BUILD_RESOURCES}") }}
            }
            steps {
                sh """
                   ${JENKINS_SCRIPTS}/global/build-repo-source.sh
                   tar -zcf ${BUILD_RESOURCES} build
                   """
            }
        }
        stage('Upload build resources') {
            steps {
                sh """
                   echo "Uploading build resources: ${BUILD_RESOURCES}"
                   """
                // Lifecycle management > build-resources-retention
                // Build resources are automatically deleted 2 days
                // the last modification
                azureUpload(
                    containerName: 'mystikos-build-resources',
                    storageType: 'container',
                    uploadZips: true,
                    filesPath: "${BUILD_RESOURCES}",
                    storageCredentialId: 'mystikosreleaseblobcontainer'
                )
            }
        }
        stage('Run Tests') {
            parallel {
                stage("Run Unit Tests") {
                    steps {
                        build job: "Helper-Pipelines/Unit-Test-Pipeline",
                        parameters: [
                            string(name: "REPOSITORY", value: REPOSITORY),
                            string(name: "BRANCH", value: BRANCH),
                            string(name: "TEST_CONFIG", value: TEST_CONFIG),
                            string(name: "BUILD_RESOURCES", value: BUILD_RESOURCES)
                        ]
                    }
                }
                stage("Run SQL Tests") {
                    steps {
                        build job: "Helper-Pipelines/SQL-Test-Pipeline",
                        parameters: [
                            string(name: "REPOSITORY", value: REPOSITORY),
                            string(name: "BRANCH", value: BRANCH),
                            string(name: "REGION", value: REGION),
                            string(name: "BUILD_RESOURCES", value: BUILD_RESOURCES)
                        ]
                    }
                }
                stage("Run DotNet Tests") {
                    steps {
                        build job: "Helper-Pipelines/DotNet-Test-Pipeline",
                        parameters: [
                            string(name: "REPOSITORY", value: REPOSITORY),
                            string(name: "BRANCH", value: BRANCH),
                            string(name: "BUILD_RESOURCES", value: BUILD_RESOURCES)
                        ]
                    }
                }
                stage("Run Azure SDK Tests") {
                    steps {
                        build job: "Helper-Pipelines/Azure-SDK-Test-Pipeline",
                        parameters: [
                            string(name: "REPOSITORY", value: REPOSITORY),
                            string(name: "BRANCH", value: BRANCH),
                            string(name: "BUILD_RESOURCES", value: BUILD_RESOURCES)
                        ]
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
