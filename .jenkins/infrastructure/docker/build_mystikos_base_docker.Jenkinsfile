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
        string(name: "BRANCH_NAME", defaultValue: "main", description: "The branch used to checkout the repository")
        string(name: "MYST_VERSION", description: "Mystikos release version (Example: 0.5.0). See https://github.com/deislabs/mystikos/releases for release versions. Alternatively can be pulled from a storage blob given a file name")
        string(name: "STORAGE_BLOB", defaultValue: '', description: '[OPTIONAL] Pull Mystikos release from a storage blob')
        string(name: "STORAGE_BLOB_CRED_ID", defaultValue: '', description: '[OPTIONAL] Credential ID to use to access STORAGE_BLOB')
        string(name: "OE_BASE_CONTAINER_TAG", defaultValue: "latest", description: "The tag for the base OE Docker container. See https://github.com/openenclave/openenclave/blob/master/DOCKER_IMAGES.md for available tags")
        string(name: "MYST_BASE_CONTAINER_TAG", defaultValue: "latest", description: "The tag for the new Mystikos base Docker container.")
        string(name: "CONTAINER_REPO", defaultValue: "https://mystikos.azurecr.io", description: "Url for internal Docker repository")
        string(name: "CONTAINER_REPO_CRED_ID", defaultValue: 'mystikos-public-container-registry', description: "Credential ID for internal Docker repository")
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: 'Version of OE Libraries to use')
        booleanParam(name: "PUBLISH", defaultValue: false, description: "Publish container to container registry?")
        booleanParam(name: "TAG_LATEST", defaultValue: false, description: "Publish container as the latest tag?")
    }
    environment {
        INTERNAL_REPO_CREDS = "${params.CONTAINER_REPO_CRED_ID}"
        BASE_DOCKERFILE_DIR = ".jenkins/docker/base/"
        OECITEAM_BRANCH = "oeciteam/publish-docker"
    }
    stages {
        stage('Initialize') {
            steps {
                script {
                    if (params.PUBLISH) {
                        if (params.OE_BASE_CONTAINER_TAG == "latest") {
                            error("Cannot publish container with latest tag for OE_BASE_CONTAINER_TAG. Please choose a tag from https://github.com/openenclave/openenclave/blob/master/DOCKER_IMAGES.md")
                        }
                        if (params.MYST_BASE_CONTAINER_TAG == "latest") {
                            error("Cannot publish container with latest tag for MYST_BASE_CONTAINER_TAG.")
                        }
                    }
                }
                cleanWs()
                checkout([$class: 'GitSCM',
                    branches: [[name: BRANCH_NAME]],
                    extensions: [],
                    userRemoteConfigs: [[url: "https://github.com/${params.REPOSITORY_NAME}"]]])
                dir(env.BASE_DOCKERFILE_DIR) {
                    script {
                        MYST_BASE_CONTAINER_TAG = params.MYST_BASE_CONTAINER_TAG ?: helpers.get_date(".") + "${BUILD_NUMBER}"
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
                        ../build.sh -m "${params.MYST_VERSION}" -o "${params.OE_BASE_CONTAINER_TAG}" -u "18.04" -t "${MYST_BASE_CONTAINER_TAG}"
                        ../build.sh -m "${params.MYST_VERSION}" -o "${params.OE_BASE_CONTAINER_TAG}" -u "20.04" -t "${MYST_BASE_CONTAINER_TAG}"
                    """
                }
            }
        }
        stage('Push base containers to internal repository') {
            when {
                expression { return params.PUBLISH }
            }
            steps {
                script {
                    docker.withRegistry(params.CONTAINER_REPO, env.INTERNAL_REPO_CREDS) {
                        base_1804_image = docker.image("mystikos-bionic:${MYST_BASE_CONTAINER_TAG}")
                        base_2004_image = docker.image("mystikos-focal:${MYST_BASE_CONTAINER_TAG}")
                        common.exec_with_retry { base_1804_image.push() }
                        common.exec_with_retry { base_2004_image.push() }

                        if ( params.TAG_LATEST ) {
                            common.exec_with_retry { base_1804_image.push('latest') }
                            common.exec_with_retry { base_2004_image.push('latest') }
                        }
                    }
                    sh "docker logout ${params.CONTAINER_REPO}"
                }
            }
        }
        stage('Publish container version information') {
            when {
                expression { return params.PUBLISH }
                expression { return params.CONTAINER_REPO ==~ /.*mystikos\.azurecr\.io/ }
            }
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: 'main']],
                    extensions: [
                        [
                            $class: 'PruneStaleBranch',
                            $class: 'SubmoduleOption',
                            disableSubmodules: true,
                            recursiveSubmodules: false,
                            trackingSubmodules: false
                        ]
                    ], 
                    userRemoteConfigs: [[url: "https://github.com/deislabs/mystikos"]]
                ])
                sh """
                    if git fetch origin ${OECITEAM_BRANCH}; then
                        git checkout ${OECITEAM_BRANCH} --force
                    else
                        git fetch origin main
                        git checkout -b ${OECITEAM_BRANCH} --track remotes/origin/main --force
                    fi
                """
                script {
                    CONTAINER_REPO = params.CONTAINER_REPO - ~"^(https|http)://"
                    BASE_2004_PSW  = helpers.dockerGetAptPackageVersion("${CONTAINER_REPO}/mystikos-focal:${MYST_BASE_CONTAINER_TAG}", "libsgx-enclave-common")
                    BASE_2004_DCAP = helpers.dockerGetAptPackageVersion("${CONTAINER_REPO}/mystikos-focal:${MYST_BASE_CONTAINER_TAG}", "libsgx-ae-id-enclave")
                    BASE_1804_PSW  = helpers.dockerGetAptPackageVersion("${CONTAINER_REPO}/mystikos-bionic:${MYST_BASE_CONTAINER_TAG}", "libsgx-enclave-common")
                    BASE_1804_DCAP = helpers.dockerGetAptPackageVersion("${CONTAINER_REPO}/mystikos-bionic:${MYST_BASE_CONTAINER_TAG}", "libsgx-ae-id-enclave")
                    println "Ubuntu 20.04 PSW: ${BASE_2004_PSW}"
                    println "Ubuntu 20.04 DCAP: ${BASE_2004_DCAP}"
                    println "Ubuntu 18.04 PSW: ${BASE_1804_PSW}"
                    println "Ubuntu 18.04 DCAP: ${BASE_1804_DCAP}"
                    if (BASE_2004_PSW == "N/A" || BASE_2004_DCAP == "N/A" || BASE_1804_PSW == "N/A" || BASE_1804_DCAP == "N/A") {
                        error("Failed to get package versions")
                    }
                }
                dir(WORKSPACE) {
                    sh """
                        if [ ! -f DOCKER_IMAGES.md ]; then
                            echo "Cannot find DOCKER_IMAGES.md"
                            exit 1
                        fi
                        echo "\$(head -n 2 DOCKER_IMAGES.md)" > DOCKER_IMAGES_new.md
                        echo "| Mystikos Base Ubuntu 20.04 | ${params.CONTAINER_REPO}/mystikos-focal:${MYST_BASE_CONTAINER_TAG} | ${params.MYST_VERSION} | ${OE_BASE_CONTAINER_TAG} | ${BASE_2004_PSW} | ${BASE_2004_DCAP} |" >> DOCKER_IMAGES_new.md
                        echo "| Mystikos Base Ubuntu 18.04 | ${params.CONTAINER_REPO}/mystikos-bionic:${MYST_BASE_CONTAINER_TAG} | ${params.MYST_VERSION} | ${OE_BASE_CONTAINER_TAG} | ${BASE_1804_PSW} | ${BASE_1804_DCAP} |" >> DOCKER_IMAGES_new.md
                        echo "\$(tail -n +3 DOCKER_IMAGES.md)" >> DOCKER_IMAGES_new.md
                        mv DOCKER_IMAGES_new.md DOCKER_IMAGES.md
                    """
                }
                withCredentials([usernamePassword(credentialsId: 'github-oeciteam-user-pat',
                                                  usernameVariable: 'GIT_USERNAME',
                                                  passwordVariable: 'GIT_PASSWORD')]) {
                    sh '''
                        git add DOCKER_IMAGES.md
                        git config --global user.email "${GIT_USERNAME}@microsoft.com"
                        git config --global user.name ${GIT_USERNAME}
                        git commit -sm "Publish Docker Images"
                        git push --force https://${GIT_PASSWORD}@github.com/deislabs/mystikos.git HEAD:${OECITEAM_BRANCH}
                    '''
                }
            }
        }
    }
}
