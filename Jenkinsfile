pipeline {
  agent any

  environment {
    WEB3_PROVIDER_URI = 'https://rpc.fullsend.to'
    CONTRACT_ADDRESS  = '0x514910771AF9Ca656af840dff83E8264EcF986CA'
    PYTHON           = 'python3'
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Install dependencies') {
      steps {
        sh '''
        set -e
        ${PYTHON} -m venv .venv
        . .venv/bin/activate
        python -m pip install --upgrade pip
        python -m pip install -e .
        python -m pip install vyper
        '''
      }
    }

    stage('Fetch bytecode & decompile') {
      steps {
        sh '''
        set -e
        . .venv/bin/activate

        BYTECODE=$(curl -s -X POST "${WEB3_PROVIDER_URI}" \
          -H "Content-Type: application/json" \
          --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"${CONTRACT_ADDRESS}\",\"latest\"]}" \
          | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")

        if [ -z "$BYTECODE" ] || [ "$BYTECODE" = "0x" ]; then
          echo "ERROR: bytecode empty for $CONTRACT_ADDRESS"
          exit 1
        fi

        panoramix "$BYTECODE" 2>/dev/null \
          | sed -r 's/\\x1B\\[[0-9;]*[A-Za-z]//g' \
          > link_decompilation.vy

        if [ ! -s link_decompilation.vy ]; then
          echo "ERROR: decompiled output empty"
          exit 1
        fi
        '''
      }
    }

    stage('Verify Vyper file') {
      steps {
        sh '''
        set -e
        if [ ! -f link_decompilation.vy ]; then
          echo "ERROR: link_decompilation.vy n'existe pas"
          exit 1
        fi
        if [ ! -s link_decompilation.vy ]; then
          echo "ERROR: link_decompilation.vy est vide"
          exit 1
        fi
        echo "OK: link_decompilation.vy existe ($(wc -l < link_decompilation.vy) lignes, $(wc -c < link_decompilation.vy) octets)"
        '''
      }
    }

    stage('Vyper syntax check') {
      steps {
        sh '''
        set -e
        . .venv/bin/activate
        vyper link_decompilation.vy > /dev/null
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'link_decompilation.vy', fingerprint: true
    }
    success {
      echo 'SUCCESS: decompilation complete and vyper check passed'
    }
    failure {
      echo 'FAIL: decompilation or vyper validation failed'
    }
  }
}
