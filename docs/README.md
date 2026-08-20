# Router Sync Configuration

Script em Python para sincronizar configurações entre roteadores Juniper MX (Produção -> Backup) de forma automática via NETCONF.

---

## 📌 O que o script faz

1. **Coleta e Compara:** Baixa a configuração dos roteadores (Produção e Backup), preservando itens de gerência do Backup (hostname, usuários, IP de gerência `fxp0`). 

**É importante você ajustar essas configurações direto no arquivo src/main.py em PROTECTED_CONFIGS.**

2. **Organiza ordem das configurações:** Como no Juniper podemos ter diferentes ordens nas mesmas configurações, o script organiza a ordem das configurações. O que foi implementado e testado em laboratório:
- Termos dentro de policy-statement
- Termos do Firewall Filter e Firewall Family inet/inet6
- Ordem dos filtros BGP de import e export, dentro do grupo BGP e dentro do neighbor.
- Ordem dos input-list e output-list das interfaces (family inet/inet6).
  
Qualquer outro item que necessite de ordem específica, deve ser implementado no Script para que seja identificado e ordenado. 

Obs.: Caso o script encontre algo que está fora de ordem e ele não consiga ajustar, vai gerar um LOG e gerar código de erro 2 (pendência de ajuste).

3. **Aplica com Segurança:** Envia as alterações usando `commit confirmed` com tempo padrão de 3 minutos, aguarda 5 segundos, faz o commit final.
4. **Notifica o Zabbix:** Envia o resultado da execução via `zabbix_sender`.

---

## 🚀 Como Executar

1. Instale as dependências:
   ```pip install -r requirements.txt
   ```

2. Execute o script:
   ```python src/main.py
   ```

---

## 📊 Monitoramento no Zabbix (v7.0.17)

O projeto inclui o arquivo **`zbx_export_hosts.yaml`** pronto para importação.

### Como importar:
1. No Zabbix, vá em **Data collection** > **Hosts** > **Import**.
2. Selecione o arquivo `zbx_export_hosts.yaml` e confirme a importação.

### O que está configurado:
- **Host:** `Router Sync Configuration`
- **Item:** `router.sync.status` *(Tipo: Zabbix trapper)*
- **Triggers configuradas:**
  - ⚠️ **Sem execução há 3 dias:** Alerta se o script não rodar ou não enviar status por mais de 3 dias (`nodata(3d)=1`).
  - 🔴 **Falha na sincronização:** Alerta quando o script encerra com erro (`status = 1`).
  - 🟡 **Alterações pendentes:** Alerta quando há regras que precisam de revisão manual (`status = 2`).

### Códigos de Retorno:
| Código | Significado |
| :---: | :--- |
| **0** | Sucesso / Sincronizado |
| **1** | Erro na sincronização |
| **2** | Pendente de revisão manual |

**Obs.: Host criado em Zabbix versão 7.0.17**

### Execução automática do Script em Debian:

1. Instalar pré-requisitos
sudo apt update
sudo apt install zabbix-sender python3 python3-venv python3-pip -y

2. Configurar ambiente virtual (considerando que a pasta do projeto está em /opt/router-sync)
cd /opt/router-sync
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

3. Abra o Cron e configure o agendamento automático (ex. às 03h todo dia):
crontab -e
# Adicione a linha abaixo para executar o script todos os dias às 03:00 da manhã
0 3 * * * cd /opt/router-sync && /opt/router-sync/.venv/bin/python src/main.py >> /opt/router-sync/logs/cron.log 2>&1
