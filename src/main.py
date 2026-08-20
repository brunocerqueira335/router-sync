import time
import logging
import re
from logging.handlers import RotatingFileHandler
import sys
import subprocess
import platform

# Importa pathlib para trabalhar com caminhos de arquivos de maneira compatível com Windows e Linux
from pathlib import Path

# Importa o PyYAML para ler arquivos YAML
import yaml

# Representa uma conexão com equipamento Juniper
from jnpr.junos import Device

# Permite tratar problemas de conexão com o equipamento Juniper
from jnpr.junos.exception import ConnectError

# Permite configurar Juniper
from jnpr.junos.utils.config import Config

# Zabbix
ip_zabbix = "192.168.200.203"
name_host = "Router Sync Configuration"


# Ajustes
# Número máximo de tentativas de sincronização
max_sync_attempts = 5

# Tempo do commit confirmed
commit_confirmed_time = 3  # em minutos

# Tempo de espera no commit confirmed antes de aplicar o commit
commit_wait_time = 5  # em segundos

logger = logging.getLogger("router_sync")

# Defini o diretório base do projeto
BASE_DIR = Path(__file__).resolve().parent.parent

# Acesso aos roteadores em formato YAML
ROUTERS_FILE = BASE_DIR / "routers" / "lab.yaml"

# Configurações dos roteadores
CONFIGS_DIR = BASE_DIR / "configs"
RAW_CONFIGS_DIR = CONFIGS_DIR / "raw"
FILTERED_CONFIGS_DIR = CONFIGS_DIR / "filtered"
LOGS_DIR = BASE_DIR / "logs"

# Configurações protegidas que não devem ser alteradas no roteador Backup
PROTECTED_CONFIGS = [
    "system host-name",
    "interfaces fxp0",
    "routing-options static route 0.0.0.0/0",
    "system root-authentication",
    "system login user",
    "interfaces ge-0/0/0"
]

# Códigos de saída para ajudar no sistema de monitoramento
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PENDING = 2

# Cria expressão regular para analisar a ordem dos termos de Firewall, Policies e Filtros BGP
POLICY_TERM_PATTERN = re.compile(
    r"^(?:set|deactivate) policy-options policy-statement (\S+) term (\S+)"
)

FIREWALL_FAMILY_TERM_PATTERN = re.compile(
    r"^(?:set|deactivate) firewall family (\S+) filter (\S+) term (\S+)"
)

FIREWALL_FILTER_TERM_PATTERN = re.compile(
    r"^(?:set|deactivate) firewall filter (\S+) term (\S+)"
)

FILTER_BGP_NEIGHBOR_IMPORT = re.compile(
    r"^(?:set|deactivate) protocols bgp group (\S+) neighbor (\S+) import (.+)"
)

FILTER_BGP_NEIGHBOR_EXPORT = re.compile(
    r"^(?:set|deactivate) protocols bgp group (\S+) neighbor (\S+) export (.+)"
)

FILTER_BGP_IMPORT = re.compile(
    r"^(?:set|deactivate) protocols bgp group (\S+) import (.+)"
)

FILTER_BGP_EXPORT = re.compile(
    r"^(?:set|deactivate) protocols bgp group (\S+) export (.+)"
)

FIREWALL_INTERFACE_IPV4_INPUT_LIST = re.compile(
    r"^(?:set|deactivate) interfaces (\S+) unit (\S+) family inet filter input-list (\S+)"
)

FIREWALL_INTERFACE_IPV4_OUTPUT_LIST = re.compile(
    r"^(?:set|deactivate) interfaces (\S+) unit (\S+) family inet filter output-list (\S+)"
)

FIREWALL_INTERFACE_IPV6_INPUT_LIST = re.compile(
    r"^(?:set|deactivate) interfaces (\S+) unit (\S+) family inet6 filter input-list (\S+)"
)

FIREWALL_INTERFACE_IPV6_OUTPUT_LIST = re.compile(
    r"^(?:set|deactivate) interfaces (\S+) unit (\S+) family inet6 filter output-list (\S+)"
)

def setup_logger():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("router_sync")
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(
        LOGS_DIR / "router_sync.log",
        maxBytes=1_000_000,
        backupCount=5,
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

# Verifica cada item do PROTECTED_CONFIGS para determinar se a linha de configuração do roteador Backup é protegida
def is_protected_config(line):
    for protected in PROTECTED_CONFIGS:
        if protected in line:
            return True
    return False

# Monta a configuração filtrando configurações protegidas do roteador Backup
def filter_protected_configs(config_text):
    filtered_lines = []
    for line in config_text.splitlines():
        if not is_protected_config(line):
            filtered_lines.append(line)
    return "\n".join(filtered_lines)

# Leitura do arquivo YAML contendo informações dos roteadores
def load_routers(ROUTERS_FILE):
    with open(ROUTERS_FILE, 'r', encoding='utf-8') as file:
        routers = yaml.safe_load(file)
    return routers

routers=load_routers(ROUTERS_FILE)

# Conectar no roteador
def connect_to_router(router):
    print(f"Conectando ao roteador {router['name']} ({router['ip']})...")
    logger.info(f"Conectando ao roteador {router['name']} ({router['ip']})...")

    try:
        dev = Device(
            host=router['ip'],
            user=router['username'],
            passwd=router['password'],
            port=router.get('port', 830),
            timeout=30
        )

        dev.open()
        print(f"Conexão estabelecida com o roteador {router['name']} ({router['ip']})!")
        logger.info(f"Conexão estabelecida com o roteador {router['name']} ({router['ip']})!")
        return dev
    
    except ConnectError as e:
        print(f"Erro ao conectar ao roteador {router['name']} ({router['ip']}): {e}")
        logger.error(f"Erro ao conectar ao roteador {router['name']} ({router['ip']}): {e}")

def get_router_config(dev):
    print(f"Obtendo configuração do roteador {dev.hostname}...")
    logger.info(f"Obtendo configuração do roteador {dev.hostname}...")
    config_text = dev.cli("show configuration | display set", warning=False)
    return config_text

def save_raw_config(router_name, config_text):
    if not config_text or not config_text.strip():
        raise ValueError(f"A configuração do roteador {router_name} está vazia. Não é possível salvar.")
    RAW_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)

    file_path = RAW_CONFIGS_DIR / f"{router_name}_config.txt"

    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(config_text)

    print(f"Configuração do roteador {router_name} salva em {file_path}")
    logger.info(f"Configuração do roteador {router_name} salva em {file_path}")

# Salva configuração filtrada em um arquivo
def save_filtered_config(router_name, config_text):
    if not config_text or not config_text.strip():
        raise ValueError(f"A configuração filtrada do roteador {router_name} está vazia. Não é possível salvar.")
    FILTERED_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)

    file_path = FILTERED_CONFIGS_DIR / f"{router_name}_filtered_config.txt"

    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(config_text)

    print(f"Configuração filtrada do roteador {router_name} salva em {file_path}")

def compare_configs(prod_config_filtered, backup_config_filtered):
    prod_lines = set(prod_config_filtered.splitlines())
    backup_lines = set(backup_config_filtered.splitlines())

    missing_in_backup = prod_lines - backup_lines
    extra_in_backup = backup_lines - prod_lines
    
    print("Comparando configurações filtradas...")
    logger.info("Comparando configurações filtradas...")

    if missing_in_backup:
        print(
        "Linhas faltando no roteador Backup:\n"
        + "\n".join(sorted(missing_in_backup))
        )
        logger.info(
            "Linhas faltando no roteador Backup:\n"
            + "\n".join(sorted(missing_in_backup))
        )
    if extra_in_backup:
        print(
        "Linhas extras no roteador Backup:\n" \
        + "\n".join(sorted(extra_in_backup)))
        logger.info(
            "Linhas extras no roteador Backup:\n"
            + "\n".join(sorted(extra_in_backup))
        )

    return missing_in_backup, extra_in_backup

def build_changes(missing_in_backup, extra_in_backup):
    changes = []
    unsupported_lines = []

    for line in extra_in_backup:
        if line.startswith("set "):
           command = "delete " + line.removeprefix("set ")
           changes.append(command)
        elif line.startswith("deactivate "):
            command = "activate " + line.removeprefix("deactivate ")
            changes.append(command)
        else:
            unsupported_lines.append(line)

    for line in missing_in_backup:
        if line.startswith(("set ","deactivate ")):
            changes.append(line)
        else:
            unsupported_lines.append(line)

    return changes, unsupported_lines

def verify_changes(changes, unsupported_lines):
    if changes:
        print("Alterações a serem aplicadas no roteador Backup:")
        logger.info("Alterações a serem aplicadas no roteador Backup:")
        for change in changes:
            print(change)
    else:
        print("Nenhuma alteração a ser aplicada no roteador Backup.")
        logger.info("Nenhuma alteração a ser aplicada no roteador Backup.")

    if unsupported_lines:
        print("\nLinhas não suportadas (não serão aplicadas):")
        logger.info("\nLinhas não suportadas (não serão aplicadas):")
        for line in sorted(unsupported_lines):
            print(line)

def apply_changes(backup_dev, changes):
    if (commit_wait_time) > (commit_confirmed_time*60):
        print(" Erro: O tempo de espera no commit confirmed é maior que o tempo do commit confirmed")
        logger.info(" Erro: O tempo de espera no commit confirmed é maior que o tempo do commit confirmed")
        return False

    cu = Config(backup_dev)
    locked = False
    try:
        # Executa rollback 0 para limpar possíveis configurações não aplicadas
        cu.rollback(rb_id=0)
        cu.lock()
        locked = True

        config_text = "\n".join(changes)
        cu.load(config_text, format='set', ignore_warning=True)
        cu.commit_check(timeout=300)

        print("\nAlterado no roteador Backup:")
        diff = cu.diff()
        print(diff)
        logger.info(f"Alterado no roteador Backup:\n{diff}")

        cu.commit(confirm=commit_confirmed_time, timeout=300)

        print(
            f"\nCommit confirmed {commit_confirmed_time} minutos iniciado. "
        )
        time.sleep(commit_wait_time)

        cu.commit(timeout=300)

        print(
            "Commit aplicado"
        )

        return True

    except Exception as error:  # noqa: BLE001
        print(f"Erro ao aplicar alterações: {error}")
        logger.error(f"Erro ao aplicar alterações: {error}")
        return False
    
    finally:
        if locked:
            cu.unlock()

def extract_ordered_terms(config_text):
    ordered_terms = {}
    unsupported_ordered_lines = []

    for line in config_text.splitlines():
        line = line.strip()

        policy_match = POLICY_TERM_PATTERN.match(line)

        if policy_match:
            policy_name, term_name = policy_match.groups()

            hierarchy = (
                f"policy-options policy-statement {policy_name}"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            if term_name not in ordered_terms[hierarchy]:
                ordered_terms[hierarchy].append(term_name)

            continue

        firewall_family_match = FIREWALL_FAMILY_TERM_PATTERN.match(line)

        if firewall_family_match:
            family_name, filter_name, term_name = firewall_family_match.groups()

            hierarchy = (
                f"firewall family {family_name} filter {filter_name}"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            if term_name not in ordered_terms[hierarchy]:
                ordered_terms[hierarchy].append(term_name)

            continue

        firewall_filter_match = FIREWALL_FILTER_TERM_PATTERN.match(line)

        if firewall_filter_match:
            filter_name, term_name = firewall_filter_match.groups()

            hierarchy = (
                f"firewall filter {filter_name}"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            if term_name not in ordered_terms[hierarchy]:
                ordered_terms[hierarchy].append(term_name)

            continue

        filter_bgp_neighbor_import_match = FILTER_BGP_NEIGHBOR_IMPORT.match(line)

        if filter_bgp_neighbor_import_match:
            group_name, neighbor_ip, import_policies = filter_bgp_neighbor_import_match.groups()

            hierarchy = (
                f"protocols bgp group {group_name} neighbor {neighbor_ip} import"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            policy_names = (
                import_policies
                .replace("[", "")
                .replace("]", "")
                .split()
            )

            for policy_name in policy_names:
                if policy_name not in ordered_terms[hierarchy]:
                    ordered_terms[hierarchy].append(policy_name)

            continue

        filter_bgp_neighbor_export_match = FILTER_BGP_NEIGHBOR_EXPORT.match(line)

        if filter_bgp_neighbor_export_match:
            group_name, neighbor_ip, export_policies = filter_bgp_neighbor_export_match.groups()

            hierarchy = (
                f"protocols bgp group {group_name} neighbor {neighbor_ip} export"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            policy_names = (
                export_policies
                .replace("[", "")
                .replace("]", "")
                .split()
            )

            for policy_name in policy_names:
                if policy_name not in ordered_terms[hierarchy]:
                    ordered_terms[hierarchy].append(policy_name)

            continue

        filter_bgp_import_match = FILTER_BGP_IMPORT.match(line)

        if filter_bgp_import_match:
            group_name, import_policies = filter_bgp_import_match.groups()

            hierarchy = (
                f"protocols bgp group {group_name} import"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            policy_names = (
                import_policies
                .replace("[", "")
                .replace("]", "")
                .split()
            )

            for policy_name in policy_names:
                if policy_name not in ordered_terms[hierarchy]:
                    ordered_terms[hierarchy].append(policy_name)

            continue

        filter_bgp_export_match = FILTER_BGP_EXPORT.match(line)

        if filter_bgp_export_match:
            group_name, export_policies = filter_bgp_export_match.groups()

            hierarchy = (
                f"protocols bgp group {group_name} export"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            policy_names = (
                export_policies
                .replace("[", "")
                .replace("]", "")
                .split()
            )

            for policy_name in policy_names:
                if policy_name not in ordered_terms[hierarchy]:
                    ordered_terms[hierarchy].append(policy_name)

            continue

        firewall_interface_ipv4_input_list = FIREWALL_INTERFACE_IPV4_INPUT_LIST.match(line)

        if firewall_interface_ipv4_input_list:
            interface_name, unit_id, input_list_name = firewall_interface_ipv4_input_list.groups()

            hierarchy = (
                f"interfaces {interface_name} unit {unit_id} family inet filter input-list"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            if input_list_name not in ordered_terms[hierarchy]:
                ordered_terms[hierarchy].append(input_list_name)

            continue

        firewall_interface_ipv4_output_list = FIREWALL_INTERFACE_IPV4_OUTPUT_LIST.match(line)

        if firewall_interface_ipv4_output_list:
            interface_name, unit_id, output_list_name = firewall_interface_ipv4_output_list.groups()

            hierarchy = (
                f"interfaces {interface_name} unit {unit_id} family inet filter output-list"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            if output_list_name not in ordered_terms[hierarchy]:
                ordered_terms[hierarchy].append(output_list_name)

            continue

        firewall_interface_ipv6_input_list = FIREWALL_INTERFACE_IPV6_INPUT_LIST.match(line)

        if firewall_interface_ipv6_input_list:
            interface_name, unit_id, input_list_name = firewall_interface_ipv6_input_list.groups()

            hierarchy = (
                f"interfaces {interface_name} unit {unit_id} family inet6 filter input-list"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            if input_list_name not in ordered_terms[hierarchy]:
                ordered_terms[hierarchy].append(input_list_name)

            continue


        firewall_interface_ipv6_output_list = FIREWALL_INTERFACE_IPV6_OUTPUT_LIST.match(line)
        
        if firewall_interface_ipv6_output_list:
            interface_name, unit_id, output_list_name = firewall_interface_ipv6_output_list.groups()

            hierarchy = (
                f"interfaces {interface_name} unit {unit_id} family inet6 filter output-list"
            )

            if hierarchy not in ordered_terms:
                ordered_terms[hierarchy] = []

            if output_list_name not in ordered_terms[hierarchy]:
                ordered_terms[hierarchy].append(output_list_name)

            continue

        if " term " in f" {line} ":
            unsupported_ordered_lines.append(line)

    return ordered_terms, unsupported_ordered_lines

# Compara ordem dos termos
def compare_ordered_terms(prod_ordered_terms, backup_ordered_terms):
    out_of_order = {}

    for hierarchy, prod_terms in prod_ordered_terms.items():
        backup_terms = backup_ordered_terms.get(hierarchy)

        if backup_terms is None:
            continue

        if prod_terms != backup_terms:
            out_of_order[hierarchy] = {
                "production": prod_terms,
                "backup": backup_terms,
            }

    return out_of_order

# Gera comandos de insert para organizar
def build_ordered_changes(out_of_order):
    ordered_changes = []
    unsupported_ordered_hierarchies = []

    for hierarchy, orders in out_of_order.items():
        prod_items = orders["production"]
        backup_items = orders["backup"]

        #insert só reorganiza itens que já existem nos dois roteadores
        if set(prod_items) != set(backup_items):
            unsupported_ordered_hierarchies.append(hierarchy)
            continue

        for index in range(1, len(prod_items)):
            previous_item = prod_items[index - 1]
            current_item = prod_items[index]

            is_term_hierarchy = (
                hierarchy.startswith("policy-options")
                or hierarchy.startswith("firewall family")
                or hierarchy.startswith("firewall filter")
            )

            if is_term_hierarchy:
                command = (
                    f"insert {hierarchy} term {current_item}"
                    f" after term {previous_item}"
                )
            else:
                command = (
                    f"insert {hierarchy} {current_item}"
                    f" after {previous_item}"
                )

            ordered_changes.append(command)

    return ordered_changes, unsupported_ordered_hierarchies

def get_zabbix_sender():
        # identifica o sistema operacional
    system = platform.system()

    if system == "Windows":
        return BASE_DIR / "tools" / "windows" / "zabbix_sender.exe"

    if system == "Linux":
        return "zabbix_sender"

    raise RuntimeError(f"Sistema operacional não suportado: {system}")

def send_status_to_zabbix(status):
    zabbix_sender = get_zabbix_sender()

    command = [
        str(zabbix_sender),
        "-z", ip_zabbix,
        "-s", name_host,
        "-k", "router.sync.status",
        "-o", str(status)
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        logger.error(
            f"Erro ao enviar status para o Zabbix: {result.stderr}"
        )
    else:
        logger.info(
            f"Status {status} enviado ao Zabbix"
        )

def main():
    setup_logger()
    routers = load_routers(ROUTERS_FILE)

    production = routers["production"]
    backup = routers["backup"]

# Pode ser necessário mais de 1 commit para sincronizar todas as configurações, então o script tentará sincronizar até 5 vezes.
    for attempt in range(1, max_sync_attempts + 1):
        if attempt > 1:
            print("\nSincronizando mais algumas algumas configurações")
            logger.info("Sincronizando mais algumas algumas configurações")

        prod_dev = connect_to_router(production)
        backup_dev = connect_to_router(backup)

        if not prod_dev or not backup_dev:
            print("Não foi possível conectar aos dois roteadores.")
            logger.error("Não foi possível conectar aos dois roteadores.")
            return EXIT_ERROR

        prod_config = get_router_config(prod_dev)
        save_raw_config(production["name"], prod_config)
        prod_dev.close()

        backup_config = get_router_config(backup_dev)
        save_raw_config(backup["name"], backup_config)
        backup_dev.close()

        prod_config_filtered = filter_protected_configs(prod_config)
        save_filtered_config(production["name"], prod_config_filtered)

        backup_config_filtered = filter_protected_configs(backup_config)
        save_filtered_config(backup["name"], backup_config_filtered)

        prod_ordered_terms, prod_unsupported_ordered_lines = (
            extract_ordered_terms(prod_config_filtered)
        )

        backup_ordered_terms, backup_unsupported_ordered_lines = (
            extract_ordered_terms(backup_config_filtered)
        )
        out_of_order = compare_ordered_terms(
            prod_ordered_terms,
            backup_ordered_terms
        )

        if prod_unsupported_ordered_lines or backup_unsupported_ordered_lines:
            print(
                "\nHá configurações que o Script não tem suporte para oganizar, favor revisar manualmente"
            )
            logger.warning(
                "\nHá configurações que o Script não tem suporte para oganizar, favor revisar manualmente"
            )

            if prod_unsupported_ordered_lines:
                print("\nProdução:")
                logger.warning("\nProdução:")

                for line in prod_unsupported_ordered_lines:
                    print(f" {line}")
                    logger.warning(" %s", line)

            if backup_unsupported_ordered_lines:
                print("\nBackup:")
                logger.warning("\nBackup:")

                for line in backup_unsupported_ordered_lines:
                    print(f" {line}")
                    logger.warning(" %s", line)

            return EXIT_PENDING

        missing_in_backup, extra_in_backup = compare_configs(
            prod_config_filtered,
            backup_config_filtered
        )

        changes, unsupported_lines = build_changes(
            missing_in_backup,
            extra_in_backup
        )

        verify_changes(changes, unsupported_lines)

        if out_of_order:
            print("Hierarquias fora de ordem:")
            logger.warning("Hierarquias fora de ordem:")

            for hierarchy, orders in out_of_order.items():
                production_order = " -> ".join(orders["production"])
                backup_order = " -> ".join(orders["backup"])

                print(f"\n{hierarchy}")
                print(f"  Produção: {production_order}")
                print(f"  Backup:   {backup_order}")

                logger.warning(
                    "%s | Produção: %s | Backup: %s",
                    hierarchy,
                    production_order,
                    backup_order,
                )

        ordered_changes, unsupported_ordered_hierarchies = (
            build_ordered_changes(out_of_order)
        )

        if unsupported_ordered_hierarchies:
            print("\nNão foi possível organizar:")
            logger.warning("\nNão foi possível organizar:")

            for hierarchy in unsupported_ordered_hierarchies:
                print(f" {hierarchy}")
                logger.warning(f" Ordenação pendente: {hierarchy}")

        if ordered_changes:
            print("\nAlterações de ordem a aplicar:")
            logger.info("\nAlterações de ordem a aplicar:")
            for command in ordered_changes:
                print(command)
                logger.info(command)

        all_changes = changes + ordered_changes

        if not all_changes:
            print("Configurações sincronizadas.")
            logger.info("Configurações sincronizadas.")
            return EXIT_OK

        apply_dev = connect_to_router(backup)

        if not apply_dev:
            print("Não foi possível reconectar ao roteador Backup.")
            logger.error("Não foi possível reconectar ao roteador Backup.")
            return EXIT_ERROR

        applied = apply_changes(apply_dev, all_changes)
        apply_dev.close()

        if not applied:
            print("Falha ao aplicar alterações. Sincronização interrompida.")
            logger.error("Falha ao aplicar alterações. Sincronização interrompida.")
            return EXIT_ERROR

    else:
        print("Ainda há configurações pendentes, favor revise manualmente.")
        logger.warning("Ainda há configurações pendentes, favor revise manualmente.")
        return EXIT_PENDING

if __name__ == "__main__":
    exit_code = main()
    send_status_to_zabbix(exit_code)
    sys.exit(exit_code)