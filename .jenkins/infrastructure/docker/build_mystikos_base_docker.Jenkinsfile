library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

pipeline {
    agent {
        label 'ACC-1804'
    }
    options {
        timeout(time: 360, unit: 'MINUTES')
    }
    parameters {
        string(name: "REPOSITORY_NAME", defaultValue: "deislabs/mystikos", description: "GitHub repository to checkout")
        string(name: "BRANCH_NAME", defaultValue: "master", description: "The branch used to checkout the repository")
        string(name: "MYST_VERSION", description: "Mystikos release version (Example: 0.5.0). See https://github.com/deislabs/mystikos/releases for release versions. Alternatively can be pulled from a storage blob given a file name")
        string(name: "STORAGE_BLOB", defaultValue: '', description: '[OPTIONAL] Pull Mystikos release from a storage blob')
        string(name: "STORAGE_BLOB_CRED_ID", defaultValue: '', description: '[OPTIONAL] Credential ID to use to access STORAGE_BLOB')
        string(name: "OE_BASE_CONTAINER_TAG", defaultValue: "SGX-2.15.100", description: "The tag for the base OE Docker container. Use SGX-<version> for releases. Example: SGX-2.15.100")
        string(name: "MYST_BASE_CONTAINER_TAG", defaultValue: "latest", description: "The tag for the new Mystikos base Docker container.")
        booleanParam(name: "PUBLISH_INTERNAL", defaultValue: false, description: "Publish container to internal registry?")
        string(name: "INTERNAL_REPO", defaultValue: "https://mystikos.azurecr.io", description: "Url for internal Docker repository")
        string(name: "INTERNAL_REPO_CRED_ID", defaultValue: 'mystikos-internal-container-registry', description: "Credential ID for internal Docker repository")
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: 'Version of OE Libraries to use')
    }
    environment {
        INTERNAL_REPO_CREDS = "${params.INTERNAL_REPO_CRED_ID}"
        BASE_DOCKERFILE_DIR = ".jenkins/docker/base/"
    }
    stages {
        stage('Initialize') {
            steps {
                cleanWs()
                checkout([$class: 'GitSCM',
                    branches: [[name: BRANCH_NAME]],
                    extensions: [],
                    userRemoteConfigs: [[url: "https://github.com/${params.REPOSITORY_NAME}"]]])
                dir(env.BASE_DOCKERFILE_DIR) {
                    script {
                        TAG_BASE_IMAGE = params.MYST_BASE_CONTAINER_TAG ?: helpers.get_date(".") + "${BUILD_NUMBER}"
                    }
                    sh """
                        chmod +x ./build.sh
                        mkdir build
                    """
                }
            }
        }
        stage("Obtain Mystikos package") {
            when {
                expression {
                    return !(params.MYST_VERSION ==~ "\\d+\\.\\d+\\.\\d+")
                }
            }
            steps {
                dir("${env.BASE_DOCKERFILE_DIR}/build") {
                    script {
                        helpers.azureContainerDownload(params.STORAGE_BLOB, params.MYST_VERSION, params.STORAGE_BLOB_CRED_ID)
                    }
                }
            }
        }
        stage('Build base container') {
            steps {
                dir("${env.BASE_DOCKERFILE_DIR}/build") {
                    sh """
                        ../build.sh -m "${params.MYST_VERSION}" -o "${params.OE_BASE_CONTAINER_TAG}" -u "18.04" -t "${TAG_BASE_IMAGE}"
                        ../build.sh -m "${params.MYST_VERSION}" -o "${params.OE_BASE_CONTAINER_TAG}" -u "20.04" -t "${TAG_BASE_IMAGE}"
                    """
                }
            }
        }
        stage('Push base containers to internal repository') {
            when {
                expression { return params.PUBLISH_INTERNAL }
            }
            steps {
                script {
                    docker.withRegistry(params.INTERNAL_REPO, env.INTERNAL_REPO_CREDS) {
                        base_1804_image = docker.image("mystikos-bionic:${TAG_BASE_IMAGE}")
                        base_2004_image = docker.image("mystikos-focal:${TAG_BASE_IMAGE}")
                        common.exec_with_retry { base_1804_image.push() }
                        common.exec_with_retry { base_2004_image.push() }

                        if ( params.MYST_BASE_CONTAINER_TAG != 'latest' ) {
                            common.exec_with_retry { base_1804_image.push('latest') }
                            common.exec_with_retry { base_2004_image.push('latest') }
                        }
                    }
                    sh "docker logout ${params.INTERNAL_REPO}"
                }
            }
        }
    }
}
