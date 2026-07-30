# Contramedida-LDoS-SDN-2026
# Sentry: Uma Contramedida Adaptativa contra Ataques de Negação de Serviço de Baixo Volume

Este repositório contém o código-fonte e os experimentos apresentados no artigo aceito no Simpósio Brasileiro de Cibersegurança (SBSeg 2026).

## Descrição
O Sentry é uma contramedida adaptativa para detecção de ataques LDoS em redes SDN. O sistema integra monitoramento do estado da rede, aprendizado seletivo e Online Isolation Forest (OIF) para detectar anomalias de forma resiliente à deriva de conceito, reduzindo a contaminação do modelo e mantendo a capacidade de adaptação ao ambiente de rede.

Resumo. Algoritmos estáticos de aprendizado de máquina tornam os sistemas de detecção de intrusão ineficazes em ambientes dinâmicos, uma vez que esses sistemas permanecem restritos aos padrões de dados observados durante a fase de treinamento. Este artigo propõe o Sentry, uma contramedida adaptativa baseada no algoritmo Online Isolation Forest, voltada à identificação de ataques de negação de serviço de baixo volume em redes definidas por software. O Sentry realiza atualizações contínuas e incorpora critérios seletivos condicionados ao estado da rede, evitando aprendizado inadequado durante períodos de ataque e reduzindo o risco de contaminação do modelo. A avaliação experimental demonstra que o Sentry supera tanto o Online Isolation Forest com atualizações irrestritas quanto o XGBoost. O Sentry atinge métricas de revocação e pontuação F1 de até 98,89% e 98,53%, respectivamente. Em contrapartida, o XGBoost e o Online Isolation Forest exibem uma queda acentuada no desempenho, com a revocação caindo para 17,95% e 10,50%, respectivamente. 

## Estrutura do Repositório
* `src/train.py`: Script para treinamento do modelo de detecção (XGBoost).
* `src/traffic.py`: Script para geração de tráfego.
* `main.py`: Scripts para execução dos testes e coleta de métricas (XGBoost, OIF e Sentry).
* `data/`: Conjunto de dados utilizado nos experimentos.
* `LICENSE`: Licença MIT de código aberto.

* ## Selos Considerados
Os autores consideram a avaliação do seguinte selo:
* Artefatos Disponíveis (SeloD)
* Arrefatos Funcionais (SeloF)

* ## Informações Básicas
Os experimentos foram conduzidos em um ambiente emulado de Software-Defined Networking (SDN), utilizando o emulador Mininet integrado a um controlador Ryu. O ambiente permite a reprodução controlada de cenários com tráfego legítimo e ataques Low-Rate Denial of Service (LDoS), com coleta de métricas em tempo real.

## Requisitos de Hardware
Os experimentos foram executados em servidor com as seguintes especificações:
* Processador: 11th Gen Intel(R) Core(TM) i9-11900K @ 3.50GHz
* Memória RAM: 128 GB DDR4 (4 × 32 GB, 3200 MHz)
* Armazenamento: 2TB 
* Sistema Operacional: Linux (Ubuntu 22.04.5 LTS)

A elevada capacidade de memória e processamento foi utilizada para garantir estabilidade experimental e minimizar interferências de contenção de recursos, não sendo estritamente necessária para reprodução dos experimentos.

## Requisitos de Software
* Ambiente Base: Python 3.8+, Mininet, Open vSwitch, Ryu (OpenFlow 1.3), iperf3 (Geração de tráfego) e Socket Python (Geração do Ataque).

## Bibliotecas
* numpy, pandas, joblib, xgboost, scikit-learn

## Preocupações com segurança
A execução dos artefatos não oferece risco de segurança para os avaliadores.

## Instalação.
* Atualização do Sistema
  
sudo apt update && sudo apt upgrade -y

* Instalação de ferramentas básicas
  
sudo apt install -y git python3 python3-pip build-essential iperf3

* Instalação das bibliotecas Python
  
pip3 install numpy pandas scikit-learn xgboost joblib

* Instalação do Mininet, Open vSwitch e utilitários de rede
  
git clone https://github.com/mininet/mininet

cd mininet

sudo ./util/install.sh -a

* Instalação do Controlador Ryu
  
pip3 install ryu

* Instalação do Online Isolation Forest (OIF)
  
  git clone https://github.com/ineveLoppiliF/Online-Isolation-Forest.git
  cd Online-Isolation-Forest
  pip3 install .

* Permissões
  
sudo chmod -R 755 /home/$USER/mininet/

* Criação do diretório de resultados.
  
mkdir -p /home/$USER/mininet/mininet/results

* Organização do Projeto
  
Os arquivos devem ser organizados conforme a seguinte estrutura:

/home/$USER/mininet/mininet/
│

├── xgboost_collector.py         

├── oif_collector.py       

├── sentry_collector.py    

├── xgboost_train.py

├── xgboost_traffic.py

├── sentry_and_oif_traffic.py

├── xgb_model.json

├── scaler.pkl

└── results/

## Teste mínimo
Este teste tem como objetivo verificar se o ambiente foi corretamente instalado e se os principais componentes do sistema estão funcionando adequadamente. O teste executa um cenário simplificado com tráfego legítimo e geração automática de dados, permitindo a validação do pipeline completo.

* Limpeza do ambiente
  
sudo mn -c

* Inicialização do controlador
  
ryu-manager ryu.app.simple_switch_13 sentry_collector.py

* Execução do cenário
  
sudo python3 sentry_and_oif_traffic.py

* Geração de arquivo CSV
  
/home/$USER/mininet/mininet/results/

Faz-se necessário a criação do seguinte caminho de diretório /home/$USER/mininet/mininet/results/ nos arquivos: sentry_collector.py   (output_dir = "results") e sentry_and_oif_traffic.py ("RESULTS_DIR = "results"). 

## Experimentos.
## Reivindicação #1 – Detecção de ataques LDoS em ambiente SDN
Esta reivindicação demonstra que o sistema proposto é capaz de detectar ataques LDoS em um ambiente SDN, combinando análise estatística de portas com classificação realizada pelo Sentry.

* Arquivos utilizados: sentry_collector.py e sentry_and_oif_traffic.py
* Tempo de duração: 540 segundos (180s de aquecimento / 180s de trafego normal / 180s de tráfego de ataque LDoS)
* Execução:
  
sudo mn -c

ryu-manager ryu.app.simple_switch_13 sentry_collector.py

sudo python3 sentry_and_oif_traffic.py

* Resultado Esperado:
  
1- Alteração da coluna "port" entre "normal" e "abnormal"

2- Registro de Classificação do modelo

3- CSV gerado em /home/$USER/mininet/mininet/results/

4- Logs do iperf em /tmp/


