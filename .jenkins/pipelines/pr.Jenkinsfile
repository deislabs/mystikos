APPROVED_AUTHORS = [
    'anakrish',
    'asvrada',
    'bodzhang',
    'CyanDevs',
    'jxyang',
    'mikbras',
    'mingweishih',
    'paulcallen',
    'radhikaj',
    'salsal97',
    'vtikoo',
    'justanotherminh'
]

// Do not trigger a full CI build if changes contain only these ignored files
IGNORED_DIRS = [
    '.jenkins/infrastructure',
    '.jenkins/docker',
    '.azure_pipelines',
    '.github',
    'doc'
]
// File name patterns to ignore using find command and -wholename option
IGNORED_PATTERNS = [
    '*/README.md'
]
IGNORED_FILES = [
    '.gitignore',
    'arch.png',
    'BUILDING.md',
    'CONTRIBUTING.md',
    'DOCKER_IMAGES.md',
    'LICENSE',
    'owners.txt',
    'README.md',
    'VERSION'
]

/* Prevent Branch Indexing from triggering a build. This is necessary because
   Branch Indexing will trigger a build for every Pull Request in the repository
   every time it occurs and waste resources.
*/
build_cause = currentBuild.getBuildCauses().toString()
if (build_cause.contains('BranchIndexingCause')) {
  currentBuild.result = 'ABORTED'
  error("Branch Indexing is not allowed. Please trigger manually or via a pull request.")
} else {
  println("Build cause: ${build_cause}")
}

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
        string(name: "REPOSITORY", defaultValue: "deislabs/mystikos")
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
                retry(5) {
                    sh """
                        while sudo lsof /var/lib/dpkg/lock-frontend | grep dpkg; do sleep 3; done
                        sudo apt-get -y --option Acquire::Retries=5 install jq
                    """
                }
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
                    // Set pull request ID for standalone builds
                    PULL_REQUEST_ID = CHANGE_ID
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
                retry(3) {
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
                                userRemoteConfigs: [[url: "https://github.com/${params.REPOSITORY}"]]]
                            )
                        }
                        GIT_COMMIT_ID = sh(
                            returnStdout: true,
                            script: "git log --max-count=1 --pretty=format:'%H'"
                        ).trim()
                        // Set pull request id for standalone builds
                        PULL_REQUEST_ID = params.PULL_REQUEST_ID
                    }
                }
            }
        }
        stage('Determine committers') {
            steps {
                script {
                    if ( params.PULL_REQUEST_ID ) {
                        // This is the git ref for a manual PR build
                        SOURCE_BRANCH = "origin/pr/${params.PULL_REQUEST_ID}"
                    } else if ( params.BRANCH != "main" ) {
                        // This is the git ref for a manual branch build
                        SOURCE_BRANCH = "origin/${params.BRANCH}"
                    } else {
                        // This is the git ref in a Jenkins multibranch pipeline build
                        SOURCE_BRANCH = "origin/PR-${env.CHANGE_ID}"
                    }
                    dir("${WORKSPACE}") {
                        COMMITTER_EMAILS = sh(
                            returnStdout: true,
                            script: "git log --pretty='%ae' origin/main..${SOURCE_BRANCH} | sort -u"
                        )
                    }
                    println(COMMITTER_EMAILS)
                }
            }
        }
        stage('Determine changes') {
            /* This stage is used to determine whether to skip the main testing stage
               if the changes are only in ignored directories or files. 
               This is only necessary for Jenkins multibranch pipeline builds.
            */
            steps {
                script {
                    dir("${WORKSPACE}") {
                        CHANGED_FILES = sh(
                            returnStdout: true,
                            script: "git diff --name-only \$(git merge-base origin/main ${SOURCE_BRANCH})..${SOURCE_BRANCH}"
                        )
                        println("All changed files in PR: ${CHANGED_FILES}")
                        for (dir in IGNORED_DIRS) {
                            FILES = sh(
                                returnStdout: true,
                                script: "find ${dir} -type f"
                            )
                            for (file in FILES.tokenize()) {
                                IGNORED_FILES.add(file)
                            }
                        }
                        for (pattern in IGNORED_PATTERNS) {
                            FILES = sh(
                                returnStdout: true,
                                script: "find . -type f -wholename '${pattern}'"
                            )
                            for (file in FILES.tokenize()) {
                                // Remove the leading ./ from the file name before adding it
                                IGNORED_FILES.add(file.substring(2))
                            }
                        }
                    }
                    println("All ignored files: ${IGNORED_FILES}")
                    // Remove ignored files from the list of changed files
                    FILES_TO_TEST = CHANGED_FILES.tokenize().minus(IGNORED_FILES)
                    println("Files to test: ${FILES_TO_TEST}")
                }
            }
        }
        stage('Run PR Tests') {
            when {
                /* Jobs must have files that need to be tested, and 
                   meet any of the situations below in order to build:
                    1. Started manually
                    2. Started by a scheduler
                    2. Triggered by a GitHub pull request to main
                */
                expression { return FILES_TO_TEST != null && ! FILES_TO_TEST.isEmpty() }
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
                        values '20.04'
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
                                            string(name: "PULL_REQUEST_ID", value: PULL_REQUEST_ID),
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
        // Bug: Post stage does not show up on Blue Ocean here
        // https://issues.jenkins.io/browse/JENKINS-58850
        always {
            script {
                if ( binding.hasVariable('COMMITTER_EMAILS') ) {
                    COMMITTER_EMAILS.tokenize('\n').each {
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
}
