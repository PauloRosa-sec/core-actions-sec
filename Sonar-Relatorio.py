#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import http.server
import socketserver
import webbrowser
import urllib3
import ssl
import warnings
from collections import defaultdict
from requests.exceptions import HTTPError, RequestException

# DESABILITA COMPLETAMENTE AVISOS SSL
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SonarQubeCollector:
    def __init__(self, base_url: str, token: str):
        """Inicializa o coletor do SonarQube"""
        self.base_url = base_url.rstrip('/')
        self.token = token
        
        # Headers padrão
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        print(f"🔧 Autenticação configurada: Bearer token")
        print(f"🔧 SSL será SEMPRE desabilitado em todas requisições")
        print()
    
    def _make_request(self, url: str, params: dict = None, timeout: int = 30) -> requests.Response:
        """Faz requisição HTTP com SSL DESABILITADO"""
        return requests.get(
            url,
            headers=self.headers,
            params=params,
            verify=False,
            timeout=timeout,
            allow_redirects=True
        )
    
    def test_connection_and_auth(self) -> bool:
        """Testa conexão E autenticação"""
        print("=" * 70)
        print("TESTANDO CONEXÃO E AUTENTICAÇÃO")
        print("=" * 70)
        
        try:
            url = f"{self.base_url}/api/system/status"
            print(f"1. Testando conexão: {url}")
            
            response = requests.get(url, verify=False, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✓ Conexão OK - SonarQube {data.get('version')} está UP")
            else:
                print(f"   ✗ Erro: Status {response.status_code}")
                return False
        except Exception as e:
            print(f"   ✗ Erro de conexão: {e}")
            return False
        
        try:
            url = f"{self.base_url}/api/projects/search"
            print(f"\n2. Testando acesso a projetos: {url}")
            
            response = self._make_request(url, params={'ps': 1})
            
            if response.status_code == 200:
                data = response.json()
                total = data.get('paging', {}).get('total', 0)
                print(f"   ✓ Acesso OK - {total} projetos disponíveis")
                print("=" * 70)
                print()
                return True
            else:
                print(f"   ✗ Erro: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"   ✗ Erro: {e}")
            return False
    
    def get_all_projects(self) -> List[Dict]:
        """Obtém todos os projetos"""
        projects = []
        page = 1
        page_size = 500
        
        print("Coletando projetos...")
        
        while True:
            url = f"{self.base_url}/api/projects/search"
            
            try:
                response = self._make_request(url, params={'p': page, 'ps': page_size})
                response.raise_for_status()
                data = response.json()
                
                components = data.get('components', [])
                projects.extend(components)
                
                total = data.get('paging', {}).get('total', 0)
                
                if len(projects) >= total or len(components) == 0:
                    break
                    
                page += 1
                
            except Exception as e:
                print(f"  ✗ Erro: {e}")
                break
        
        print(f"✓ {len(projects)} projetos coletados")
        return projects
    
    def get_project_branches(self, project_key: str) -> List[Dict]:
        """Obtém branches do projeto"""
        url = f"{self.base_url}/api/project_branches/list"
        
        try:
            response = self._make_request(url, params={'project': project_key})
            response.raise_for_status()
            return response.json().get('branches', [])
        except Exception as e:
            print(f"    ⚠ Erro ao obter branches: {e}")
            return []
    
    def get_metrics_history(self, project_key: str, metrics: str, from_date: str = None, branch: str = None) -> List[Dict]:
        """Obtém histórico de métricas"""
        url = f"{self.base_url}/api/measures/search_history"
        params = {
            'component': project_key,
            'metrics': metrics,
            'ps': 1000
        }
        
        if from_date:
            params['from'] = from_date
        
        if branch:
            params['branch'] = branch
        
        try:
            response = self._make_request(url, params=params)
            response.raise_for_status()
            data = response.json()
            measures = data.get('measures', [])
            
            if measures:
                print(f"    ✓ Histórico de {metrics}: {len(measures[0].get('history', []))} pontos")
            
            return measures
        except Exception as e:
            print(f"    ⚠ Erro ao obter histórico de {metrics}: {e}")
            return []
    
    def get_quality_gate_status(self, project_key: str, branch: str = None) -> str:
        """Obtém o status atual do Quality Gate (OK/ERROR/NONE)"""
        url = f"{self.base_url}/api/qualitygates/project_status"
        params = {'projectKey': project_key}
        
        if branch:
            params['branch'] = branch
        
        try:
            response = self._make_request(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            status = data.get('projectStatus', {}).get('status', 'NONE')
            return status
        except Exception as e:
            return 'NONE'
    
    def get_quality_gate_history(self, project_key: str, days: int = 30, branch: str = None) -> List[Dict]:
        """Obtém histórico de Quality Gate"""
        url = f"{self.base_url}/api/project_analyses/search"
        params = {
            'project': project_key,
            'ps': 100
        }
        
        if branch:
            params['branch'] = branch
        
        try:
            response = self._make_request(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            analyses = data.get('analyses', [])
            from_date = datetime.now() - timedelta(days=days)
            
            history = []
            for analysis in analyses:
                try:
                    date = datetime.fromisoformat(analysis['date'].replace('Z', '+00:00'))
                    if date >= from_date:
                        # Procurar evento de Quality Gate
                        qg_status = 'UNKNOWN'
                        for event in analysis.get('events', []):
                            if event.get('category') == 'QUALITY_GATE':
                                qg_status = event.get('name', 'UNKNOWN')
                                break
                        
                        history.append({
                            'date': analysis['date'],
                            'status': qg_status
                        })
                except:
                    continue
            
            print(f"    ✓ Histórico QG: {len(history)} análises")
            return history
        except Exception as e:
            print(f"    ⚠ Erro ao obter QG history: {e}")
            return []
    
    def get_issues_detailed(self, project_key: str, branch: str = None) -> List[Dict]:
        """Obtém issues detalhados"""
        issues = []
        page = 1
        page_size = 500
        
        print(f"    → Coletando issues...")
        
        while True:
            url = f"{self.base_url}/api/issues/search"
            params = {
                'componentKeys': project_key,
                'p': page,
                'ps': page_size,
                'resolved': 'false',
                'additionalFields': 'comments'
            }
            
            if branch:
                params['branch'] = branch
            
            try:
                response = self._make_request(url, params=params)
                response.raise_for_status()
                data = response.json()
                
                batch = data.get('issues', [])
                issues.extend(batch)
                
                total = data.get('total', 0)
                
                if len(issues) >= total or len(batch) == 0:
                    break
                
                page += 1
                
                if page > 10:  # Limitar para não demorar muito
                    break
                    
            except Exception as e:
                print(f"      ⚠ Erro na página {page}: {e}")
                break
        
        print(f"    ✓ Issues coletados: {len(issues)}")
        
        # Contar blockers
        blockers = [i for i in issues if i.get('severity') == 'BLOCKER']
        if blockers:
            print(f"    🔴 BLOCKERS encontrados: {len(blockers)}")
        
        return issues
    
    def get_hotspots(self, project_key: str, branch: str = None) -> List[Dict]:
        """Obtém security hotspots"""
        hotspots = []
        page = 1
        page_size = 500
        
        print(f"    → Coletando hotspots...")
        
        while True:
            url = f"{self.base_url}/api/hotspots/search"
            params = {
                'projectKey': project_key,
                'p': page,
                'ps': page_size
            }
            
            if branch:
                params['branch'] = branch
            
            try:
                response = self._make_request(url, params=params)
                response.raise_for_status()
                data = response.json()
                
                batch = data.get('hotspots', [])
                hotspots.extend(batch)
                
                paging = data.get('paging', {})
                total = paging.get('total', 0)
                
                if len(hotspots) >= total or len(batch) == 0:
                    break
                
                page += 1
                
                if page > 20:  # Limitar para não travar
                    break
                    
            except HTTPError as e:
                if e.response.status_code == 404:
                    print(f"      ⚠ API de hotspots não disponível ou branch não encontrada")
                else:
                    print(f"      ⚠ Erro HTTP {e.response.status_code} ao coletar hotspots")
                break
            except RequestException as e:
                print(f"      ⚠ Erro ao coletar hotspots: {e}")
                break
        
        print(f"    ✓ Hotspots coletados: {len(hotspots)}")
        return hotspots
    
    def get_current_metrics(self, project_key: str, branch: str = None) -> Dict:
        """Obtém métricas atuais"""
        url = f"{self.base_url}/api/measures/component"
        params = {
            'component': project_key,
            'metricKeys': 'coverage,bugs,vulnerabilities,code_smells,duplicated_lines_density,ncloc,security_hotspots,sqale_index,reliability_rating,security_rating,sqale_rating,blocker_violations,critical_violations,major_violations,minor_violations,info_violations,new_bugs,new_vulnerabilities,new_code_smells'
        }
        
        if branch:
            params['branch'] = branch
        
        try:
            response = self._make_request(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            measures = data.get('component', {}).get('measures', [])
            metrics = {}
            
            for measure in measures:
                key = measure.get('metric')
                value = measure.get('value', '0')
                
                if 'rating' in key:
                    metrics[key] = value
                else:
                    try:
                        metrics[key] = float(value)
                    except:
                        metrics[key] = value
            
            return metrics
        except Exception as e:
            print(f"      ⚠ Erro ao obter métricas: {e}")
            return {}
    
    def collect_dashboard_data(self) -> Dict:
        """Coleta todos os dados para o dashboard"""
        print("\n" + "=" * 70)
        print("COLETANDO DADOS PARA DASHBOARD")
        print("=" * 70)
        print()
        print("ℹ️  Coletando TODAS as branches de cada projeto...")
        print("ℹ️  Isso pode demorar alguns minutos dependendo do número de projetos.")
        print()
        
        all_projects = self.get_all_projects()
        dashboard_data = {
            'collection_date': datetime.now().isoformat(),
            'sonar_url': self.base_url,
            'total_projects': len(all_projects),
            'projects_main_passed': 0,
            'projects_main_failed': 0,
            'projects_main_none': 0,
            'projects': []
        }
        
        for idx, project in enumerate(all_projects, 1):
            project_key = project.get('key')
            project_name = project.get('name')
            
            print(f"\n[{idx}/{len(all_projects)}] {project_name}")
            print(f"  Key: {project_key}")
            
            branches = self.get_project_branches(project_key)
            
            if not branches:
                print("  ⚠ Sem branches - usando branch padrão")
                branches = [{'name': 'main', 'isMain': True, 'type': 'BRANCH'}]
            
            project_data = {
                'key': project_key,
                'name': project_name,
                'branches': [],
                'main_qg_status': 'NONE'
            }
            
            # Processar TODAS as branches (sem limitação)
            for branch in branches:
                branch_name = branch.get('name')
                is_main = branch.get('isMain', False)
                
                print(f"\n  📍 Branch: {branch_name} {'(Principal)' if is_main else ''}")
                
                try:
                    # 1. Métricas atuais
                    print(f"    → Coletando métricas atuais...")
                    current_metrics = self.get_current_metrics(project_key, branch_name)
                    
                    if current_metrics:
                        cov = current_metrics.get('coverage', 0)
                        bugs = current_metrics.get('bugs', 0)
                        vulns = current_metrics.get('vulnerabilities', 0)
                        print(f"    ✓ Cobertura: {cov:.1f}%, Bugs: {int(bugs)}, Vulns: {int(vulns)}")
                    
                    # 1.5. Status do Quality Gate (especialmente para main/master)
                    qg_status = 'NONE'
                    if is_main or branch_name.lower() in ['main', 'master']:
                        qg_status = self.get_quality_gate_status(project_key, branch_name)
                        print(f"    ✓ Quality Gate: {qg_status}")
                        
                        # Atualizar status do projeto (usa o da branch principal)
                        project_data['main_qg_status'] = qg_status
                    
                    # 2. Histórico de cobertura (90 dias)
                    from_date_90 = (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%d')
                    coverage_history = self.get_metrics_history(
                        project_key, 
                        'coverage', 
                        from_date_90,
                        branch_name
                    )
                    
                    # 3. Histórico de bugs e vulnerabilidades (30 dias)
                    from_date_30 = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
                    bugs_history = self.get_metrics_history(
                        project_key,
                        'bugs,vulnerabilities',
                        from_date_30,
                        branch_name
                    )
                    
                    # 4. Histórico de Quality Gate
                    qg_history = self.get_quality_gate_history(project_key, 30, branch_name)
                    
                    # 5. Issues detalhados
                    issues = self.get_issues_detailed(project_key, branch_name)
                    
                    # 6. Hotspots
                    hotspots = self.get_hotspots(project_key, branch_name)
                    
                    # Processar issues
                    issues_by_type = defaultdict(int)
                    issues_by_severity = defaultdict(int)
                    rules_count = defaultdict(int)
                    issues_by_date = defaultdict(lambda: {'bugs': 0, 'vulnerabilities': 0})
                    blocker_issues = []
                    
                    for issue in issues:
                        issue_type = issue.get('type', 'UNKNOWN')
                        severity = issue.get('severity', 'UNKNOWN')
                        rule = issue.get('rule', 'UNKNOWN')
                        creation_date = issue.get('creationDate', '')
                        
                        issues_by_type[issue_type] += 1
                        issues_by_severity[severity] += 1
                        rules_count[rule] += 1
                        
                        # Separar blockers com informações completas
                        if severity == 'BLOCKER':
                            blocker_issues.append({
                                'key': issue.get('key', ''),
                                'message': issue.get('message', 'Sem descrição'),
                                'component': issue.get('component', '').split(':')[-1] if ':' in issue.get('component', '') else issue.get('component', ''),
                                'line': issue.get('line', 0),
                                'type': issue_type,
                                'rule': rule,
                                'creationDate': creation_date
                            })
                        
                        # Agrupar por semana para new code trend
                        if creation_date:
                            try:
                                date = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                                week = date.strftime('%Y-W%W')
                                if issue_type == 'BUG':
                                    issues_by_date[week]['bugs'] += 1
                                elif issue_type == 'VULNERABILITY':
                                    issues_by_date[week]['vulnerabilities'] += 1
                            except:
                                pass
                    
                    # Processar hotspots
                    hotspots_by_status = defaultdict(int)
                    for hotspot in hotspots:
                        status = hotspot.get('status', 'TO_REVIEW')
                        hotspots_by_status[status] += 1
                    
                    # Calcular MTTR (simulado baseado em issues resolvidos nos últimos 30 dias)
                    mttr_data = {
                        'bugs': 0,
                        'vulnerabilities': 0,
                        'code_smells': 0
                    }
                    
                    branch_data = {
                        'name': branch_name,
                        'is_main': is_main,
                        'qg_status': qg_status,
                        'current_metrics': current_metrics,
                        'coverage_history': coverage_history,
                        'bugs_history': bugs_history,
                        'qg_history': qg_history,
                        'issues_by_type': dict(issues_by_type),
                        'issues_by_severity': dict(issues_by_severity),
                        'rules_count': dict(rules_count),
                        'hotspots_by_status': dict(hotspots_by_status),
                        'issues_by_date': dict(issues_by_date),
                        'blocker_issues': blocker_issues,
                        'mttr_data': mttr_data,
                        'total_issues': len(issues),
                        'total_hotspots': len(hotspots)
                    }
                    
                    project_data['branches'].append(branch_data)
                    
                except Exception as e:
                    print(f"    ✗ Erro ao processar branch {branch_name}: {e}")
                    print(f"    → Continuando com próxima branch...")
                    continue
            
            dashboard_data['projects'].append(project_data)
            
            # Incrementar contadores de status do Quality Gate
            main_status = project_data['main_qg_status']
            if main_status == 'OK':
                dashboard_data['projects_main_passed'] += 1
            elif main_status == 'ERROR':
                dashboard_data['projects_main_failed'] += 1
            else:
                dashboard_data['projects_main_none'] += 1
            
            # Resumo do projeto
            branches_ok = len(project_data['branches'])
            branches_total = len(branches)
            if branches_ok < branches_total:
                print(f"  ⚠ {branches_ok}/{branches_total} branches processadas com sucesso")
            else:
                print(f"  ✓ {branches_ok} branch(es) processada(s) com sucesso")
        
        print("\n" + "=" * 70)
        total_branches = sum(len(p['branches']) for p in dashboard_data['projects'])
        total_blockers = sum(len(b.get('blocker_issues', [])) for p in dashboard_data['projects'] for b in p['branches'])
        
        print(f"✓ Coleta concluída:")
        print(f"  - {len(all_projects)} projetos/repositórios no total")
        print(f"  - {total_branches} branches coletadas")
        
        if total_blockers > 0:
            print(f"\n⚠️  ATENÇÃO:")
            print(f"  - 🔴 {total_blockers} issues BLOCKER encontrados!")
            print(f"  - Issues BLOCKER requerem ação IMEDIATA!")
        else:
            print(f"\n✅ Nenhum issue BLOCKER encontrado!")
        
        print(f"\n📊 Status Quality Gate (Branch Main/Master):")
        print(f"  - ✅ PASSED: {dashboard_data['projects_main_passed']} projetos")
        print(f"  - ❌ FAILED: {dashboard_data['projects_main_failed']} projetos")
        print(f"  - ⚪ SEM STATUS: {dashboard_data['projects_main_none']} projetos")
        print("=" * 70)
        
        return dashboard_data
    
    def generate_dashboard_html(self, data: Dict) -> str:
        """Gera HTML do dashboard"""
        collection_date = datetime.fromisoformat(data['collection_date']).strftime('%d/%m/%Y %H:%M:%S')
        sonar_url = data.get('sonar_url', '#')
        
        # Converter dados para JSON
        data_json = json.dumps(data, ensure_ascii=False, default=str)
        
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SonarQube Dashboard Avançado</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f6fa;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .date {{ opacity: 0.9; font-size: 1.1em; }}
        
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            gap: 20px;
            transition: transform 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .stat-icon {{
            font-size: 3em;
            line-height: 1;
        }}
        
        .stat-content {{
            flex: 1;
        }}
        
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            line-height: 1;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.95em;
            margin-bottom: 5px;
        }}
        
        .stat-percentage {{
            color: #999;
            font-size: 0.9em;
            font-weight: 600;
        }}
        
        .stat-total .stat-value {{ color: #667eea; }}
        .stat-passed .stat-value {{ color: #28a745; }}
        .stat-failed .stat-value {{ color: #dc3545; }}
        .stat-none .stat-value {{ color: #9e9e9e; }}
        
        .filters {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .filters h2 {{ color: #333; margin-bottom: 20px; font-size: 1.5em; }}
        
        .filter-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }}
        
        .filter-item {{ display: flex; flex-direction: column; }}
        .filter-item label {{ font-weight: 600; color: #555; margin-bottom: 8px; }}
        
        .filter-item select,
        .filter-item input {{
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s;
        }}
        
        .filter-item select:focus,
        .filter-item input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        .cards-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 25px;
        }}
        
        .card {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        
        .card:hover {{ transform: translateY(-5px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }}
        .card.full-width {{ grid-column: 1 / -1; }}
        
        .card h3 {{
            color: #333;
            margin-bottom: 20px;
            font-size: 1.3em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .kpi-item {{
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
        }}
        
        .kpi-value {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .kpi-label {{ color: #666; font-size: 0.9em; margin-top: 5px; }}
        
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th {{ background: #667eea; color: white; padding: 12px; text-align: left; font-weight: 600; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #e0e0e0; }}
        tr:hover {{ background: #f8f9fa; }}
        
        .chart-container {{ position: relative; height: 300px; margin-top: 15px; }}
        
        .heatmap {{
            display: grid;
            grid-template-columns: repeat(30, 1fr);
            gap: 5px;
            margin-top: 15px;
        }}
        
        .heatmap-cell {{
            aspect-ratio: 1;
            border-radius: 4px;
            cursor: pointer;
            position: relative;
        }}
        
        .heatmap-cell.passed {{ background: #28a745; }}
        .heatmap-cell.failed {{ background: #dc3545; }}
        .heatmap-cell.unknown {{ background: #e0e0e0; }}
        
        .score-bad {{ color: #dc3545; font-weight: bold; }}
        .score-medium {{ color: #ff9800; font-weight: bold; }}
        .score-good {{ color: #28a745; font-weight: bold; }}
        
        .empty-state {{ text-align: center; padding: 40px; color: #999; font-style: italic; }}
        
        a {{ color: #667eea; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        
        button {{
            cursor: pointer;
            transition: all 0.3s;
        }}
        
        button:hover {{
            opacity: 0.8;
            transform: translateY(-2px);
        }}
        
        button:active {{
            transform: translateY(0);
        }}
        
        .blocker-item {{
            background: rgba(255,255,255,0.1);
            border-left: 4px solid #ff0000;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }}
        
        .blocker-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
        }}
        
        .blocker-title {{
            font-weight: bold;
            font-size: 1.1em;
            flex: 1;
        }}
        
        .blocker-badge {{
            background: #ff0000;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .blocker-details {{
            color: rgba(255,255,255,0.9);
            font-size: 0.9em;
            margin-top: 8px;
        }}
        
        .blocker-meta {{
            display: flex;
            gap: 15px;
            margin-top: 10px;
            font-size: 0.85em;
            color: rgba(255,255,255,0.7);
        }}
        
        .blocker-link {{
            color: #ffd93d;
            text-decoration: none;
            font-weight: 600;
        }}
        
        .blocker-link:hover {{
            text-decoration: underline;
        }}
        
        .overview-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .overview-item {{
            text-align: center;
            padding: 20px;
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }}
        
        .overview-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .overview-label {{
            font-size: 0.95em;
            opacity: 0.9;
        }}
        
        .sdlc-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .sdlc-kpi {{
            background: rgba(255,255,255,0.15);
            padding: 20px;
            border-radius: 12px;
            backdrop-filter: blur(10px);
            border: 2px solid rgba(255,255,255,0.2);
            position: relative;
            overflow: hidden;
        }}
        
        .sdlc-kpi::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: currentColor;
        }}
        
        .sdlc-kpi.excellent {{ color: #00ff88; }}
        .sdlc-kpi.good {{ color: #4caf50; }}
        .sdlc-kpi.warning {{ color: #ffd93d; }}
        .sdlc-kpi.danger {{ color: #ff6b6b; }}
        .sdlc-kpi.critical {{ color: #ff0000; }}
        
        .sdlc-label {{
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .sdlc-value {{
            font-size: 2.5em;
            font-weight: bold;
            line-height: 1;
            margin-bottom: 8px;
        }}
        
        .sdlc-subtitle {{
            font-size: 0.85em;
            opacity: 0.8;
        }}
        
        .sdlc-trend {{
            display: inline-flex;
            align-items: center;
            gap: 4px;
            font-size: 0.9em;
            margin-top: 5px;
            padding: 4px 8px;
            background: rgba(0,0,0,0.2);
            border-radius: 6px;
        }}
        
        .sdlc-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            background: rgba(255,255,255,0.2);
            margin-top: 8px;
        }}
        
        .sdlc-section {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 2px solid rgba(255,255,255,0.2);
        }}
        
        .sdlc-section-title {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 15px;
            opacity: 0.95;
        }}
        
        .progress-bar {{
            width: 100%;
            height: 8px;
            background: rgba(0,0,0,0.2);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 8px;
        }}
        
        .progress-fill {{
            height: 100%;
            background: currentColor;
            transition: width 0.3s ease;
        }}
        
        .metric-comparison {{
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 0.85em;
            opacity: 0.8;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 SonarQube Dashboard Avançado</h1>
        <div class="date">Atualizado em: {collection_date}</div>
    </div>
    
    <div class="summary-stats">
        <div class="stat-card stat-total">
            <div class="stat-icon">🏢</div>
            <div class="stat-content">
                <div class="stat-value" id="totalProjects">0</div>
                <div class="stat-label">Repositórios Totais</div>
            </div>
        </div>
        
        <div class="stat-card stat-passed">
            <div class="stat-icon">✅</div>
            <div class="stat-content">
                <div class="stat-value" id="projectsPassed">0</div>
                <div class="stat-label">Main Branch PASSED</div>
                <div class="stat-percentage" id="passedPercentage">0%</div>
            </div>
        </div>
        
        <div class="stat-card stat-failed">
            <div class="stat-icon">❌</div>
            <div class="stat-content">
                <div class="stat-value" id="projectsFailed">0</div>
                <div class="stat-label">Main Branch FAILED</div>
                <div class="stat-percentage" id="failedPercentage">0%</div>
            </div>
        </div>
        
        <div class="stat-card stat-none">
            <div class="stat-icon">⚪</div>
            <div class="stat-content">
                <div class="stat-value" id="projectsNone">0</div>
                <div class="stat-label">Sem Status QG</div>
                <div class="stat-percentage" id="nonePercentage">0%</div>
            </div>
        </div>
        
        <div class="stat-card" style="background: linear-gradient(135deg, #ff6b6b 0%, #c92a2a 100%); color: white;">
            <div class="stat-icon">🔴</div>
            <div class="stat-content">
                <div class="stat-value" id="totalBlockers" style="color: white;">0</div>
                <div class="stat-label" style="color: rgba(255,255,255,0.9);">Issues BLOCKER</div>
                <div class="stat-percentage" style="color: rgba(255,255,255,0.7);" id="blockersInfo">Ação imediata!</div>
            </div>
        </div>
    </div>
    
    <div class="filters">
        <h2>🔍 Filtros</h2>
        <div class="filter-grid">
            <div class="filter-item">
                <label for="filterProject">Projeto</label>
                <select id="filterProject" onchange="applyFilters()">
                    <option value="">Todos os Projetos</option>
                </select>
            </div>
            
            <div class="filter-item">
                <label for="filterBranch">Branch</label>
                <select id="filterBranch" onchange="applyFilters()">
                    <option value="">Todas as Branches</option>
                </select>
            </div>
            
            <div class="filter-item">
                <label for="filterSeverity">Severidade</label>
                <select id="filterSeverity" onchange="applyFilters()">
                    <option value="">Todas</option>
                    <option value="BLOCKER">Blocker</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="MAJOR">Major</option>
                    <option value="MINOR">Minor</option>
                    <option value="INFO">Info</option>
                </select>
            </div>
            
            <div class="filter-item">
                <label for="filterType">Tipo</label>
                <select id="filterType" onchange="applyFilters()">
                    <option value="">Todos</option>
                    <option value="BUG">Bug</option>
                    <option value="VULNERABILITY">Vulnerability</option>
                    <option value="CODE_SMELL">Code Smell</option>
                </select>
            </div>
        </div>
    </div>
    
    <div class="cards-container">
        <div class="card full-width" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
            <h3 style="color: white; border-bottom-color: rgba(255,255,255,0.3);">📦 Visão Geral dos Repositórios</h3>
            <div id="projectsOverview"></div>
        </div>
        
        <div class="card full-width" style="background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white;">
            <h3 style="color: white; border-bottom-color: rgba(255,255,255,0.3);">
                📊 KPIs SDLC - Gestão Executiva
                <span style="float: right; font-size: 0.7em; opacity: 0.8; font-weight: normal;">
                    🟢 Excelente | 🔵 Bom | 🟡 Atenção | 🟠 Crítico | 🔴 Urgente
                </span>
            </h3>
            <div id="sdlcKpisContainer"></div>
        </div>
        
        <div class="card full-width" style="background: linear-gradient(135deg, #ff6b6b 0%, #c92a2a 100%); color: white;">
            <h3 style="color: white; border-bottom-color: rgba(255,255,255,0.3);">🔴 BLOCKERS - Issues Críticos</h3>
            <div id="blockersContainer"></div>
        </div>
        
        <div class="card full-width">
            <h3>📈 KPIs Gerais por Projeto</h3>
            <div id="kpisContainer"></div>
        </div>
        
        <div class="card full-width">
            <h3>🎯 Status Quality Gate - Branch Main/Master</h3>
            <div id="qgStatusTable"></div>
        </div>
        
        <div class="card full-width">
            <h3>🎯 Quality Gate Status (Últimos 30 Dias)</h3>
            <div id="qgHeatmap"></div>
        </div>
        
        <div class="card">
            <h3>📊 Tendência de Cobertura (90 Dias)</h3>
            <div class="chart-container">
                <canvas id="coverageTrendChart"></canvas>
            </div>
        </div>
        
        <div class="card">
            <h3>🔴 Issues por Severidade</h3>
            <div class="chart-container">
                <canvas id="vulnSeverityChart"></canvas>
            </div>
        </div>
        
        <div class="card">
            <h3>⏱️ MTTR Médio por Tipo</h3>
            <div id="mttrContainer"></div>
        </div>
        
        <div class="card">
            <h3>🛡️ Security Hotspots por Status</h3>
            <div class="chart-container">
                <canvas id="hotspotsChart"></canvas>
            </div>
        </div>
        
        <div class="card full-width">
            <h3>📋 Top 10 Regras Mais Violadas</h3>
            <div id="topRulesContainer"></div>
        </div>
        
        <div class="card full-width">
            <h3>⚠️ Projetos em Pior Estado (Score Composto)</h3>
            <div id="worstProjectsContainer"></div>
        </div>
        
        <div class="card full-width">
            <h3>🆕 Trend de Issues por Semana</h3>
            <div class="chart-container">
                <canvas id="newCodeTrendChart"></canvas>
            </div>
        </div>
    </div>
    
    <script>
    const dashboardData = {data_json};
    const sonarUrl = "{sonar_url}";
    let filteredData = dashboardData;
    let charts = {{}};
    
    document.addEventListener('DOMContentLoaded', function() {{
        console.log('Dashboard data:', dashboardData);
        updateSummaryStats();
        initializeFilters();
        renderDashboard();
    }});
    
    function updateSummaryStats() {{
        // Usar dados filtrados se houver filtro ativo, senão usar dados completos
        const data = filteredData;
        
        const total = data.projects ? data.projects.length : 0;
        let passed = 0;
        let failed = 0;
        let none = 0;
        let totalBlockers = 0;
        
        if (data.projects) {{
            data.projects.forEach(project => {{
                const status = project.main_qg_status;
                if (status === 'OK') passed++;
                else if (status === 'ERROR') failed++;
                else none++;
                
                // Contar blockers
                project.branches.forEach(branch => {{
                    totalBlockers += (branch.blocker_issues || []).length;
                }});
            }});
        }}
        
        document.getElementById('totalProjects').textContent = total;
        document.getElementById('projectsPassed').textContent = passed;
        document.getElementById('projectsFailed').textContent = failed;
        document.getElementById('projectsNone').textContent = none;
        document.getElementById('totalBlockers').textContent = totalBlockers;
        
        if (totalBlockers > 0) {{
            document.getElementById('blockersInfo').textContent = 'Ação imediata necessária!';
        }} else {{
            document.getElementById('blockersInfo').textContent = 'Tudo limpo! 🎉';
        }}
        
        if (total > 0) {{
            document.getElementById('passedPercentage').textContent = `(${{((passed / total) * 100).toFixed(1)}}%)`;
            document.getElementById('failedPercentage').textContent = `(${{((failed / total) * 100).toFixed(1)}}%)`;
            document.getElementById('nonePercentage').textContent = `(${{((none / total) * 100).toFixed(1)}}%)`;
        }} else {{
            document.getElementById('passedPercentage').textContent = '(0%)';
            document.getElementById('failedPercentage').textContent = '(0%)';
            document.getElementById('nonePercentage').textContent = '(0%)';
        }}
    }}
    
    function initializeFilters() {{
        const projectSelect = document.getElementById('filterProject');
        dashboardData.projects.forEach(project => {{
            const option = document.createElement('option');
            option.value = project.key;
            option.textContent = project.name;
            projectSelect.appendChild(option);
        }});
    }}
    
    function applyFilters() {{
        const projectFilter = document.getElementById('filterProject').value;
        const branchFilter = document.getElementById('filterBranch').value;
        
        filteredData = JSON.parse(JSON.stringify(dashboardData));
        
        if (projectFilter) {{
            filteredData.projects = filteredData.projects.filter(p => p.key === projectFilter);
        }}
        
        if (branchFilter) {{
            filteredData.projects.forEach(project => {{
                project.branches = project.branches.filter(b => b.name === branchFilter);
            }});
        }}
        
        updateBranchFilter();
        updateSummaryStats();
        renderDashboard();
    }}
    
    function updateBranchFilter() {{
        const projectFilter = document.getElementById('filterProject').value;
        const branchSelect = document.getElementById('filterBranch');
        
        branchSelect.innerHTML = '<option value="">Todas as Branches</option>';
        
        if (projectFilter) {{
            const project = dashboardData.projects.find(p => p.key === projectFilter);
            if (project) {{
                project.branches.forEach(branch => {{
                    const option = document.createElement('option');
                    option.value = branch.name;
                    option.textContent = branch.name;
                    branchSelect.appendChild(option);
                }});
            }}
        }}
    }}
    
    function renderDashboard() {{
        renderProjectsOverview();
        renderSDLCKPIs();
        renderBlockers();
        renderQGStatusTable();
        renderKPIs();
        renderQGHeatmap();
        renderCoverageTrend();
        renderVulnSeverity();
        renderMTTR();
        renderHotspots();
        renderTopRules();
        renderWorstProjects();
        renderNewCodeTrend();
    }}
    
    function renderSDLCKPIs() {{
        const container = document.getElementById('sdlcKpisContainer');
        
        if (!filteredData.projects || filteredData.projects.length === 0) {{
            container.innerHTML = '<div class="empty-state" style="color: rgba(255,255,255,0.7);">Nenhum projeto encontrado</div>';
            return;
        }}
        
        // Calcular métricas agregadas
        let totalProjects = filteredData.projects.length;
        let projectsWithQG = 0;
        let projectsQGPassed = 0;
        let totalCoverage = 0;
        let projectsWithCoverage = 0;
        let totalDuplication = 0;
        let projectsWithDuplication = 0;
        let totalBugs = 0;
        let totalVulns = 0;
        let totalCodeSmells = 0;
        let totalLOC = 0;
        let totalHotspots = 0;
        let projectsWithBlockers = 0;
        let projectsWithCritical = 0;
        let securityRatings = [];
        let reliabilityRatings = [];
        let maintainabilityRatings = [];
        
        filteredData.projects.forEach(project => {{
            // Quality Gate
            if (project.main_qg_status !== 'NONE') {{
                projectsWithQG++;
                if (project.main_qg_status === 'OK') {{
                    projectsQGPassed++;
                }}
            }}
            
            project.branches.forEach(branch => {{
                const m = branch.current_metrics || {{}};
                
                // Cobertura
                if (m.coverage > 0) {{
                    totalCoverage += m.coverage;
                    projectsWithCoverage++;
                }}
                
                // Duplicação
                if (m.duplicated_lines_density !== undefined) {{
                    totalDuplication += m.duplicated_lines_density;
                    projectsWithDuplication++;
                }}
                
                // Issues
                totalBugs += m.bugs || 0;
                totalVulns += m.vulnerabilities || 0;
                totalCodeSmells += m.code_smells || 0;
                totalHotspots += m.security_hotspots || 0;
                
                // LOC (Lines of Code)
                totalLOC += m.ncloc || 0;
                
                // Ratings
                if (m.security_rating) securityRatings.push(m.security_rating);
                if (m.reliability_rating) reliabilityRatings.push(m.reliability_rating);
                if (m.sqale_rating) maintainabilityRatings.push(m.sqale_rating);
                
                // Severidade
                const blockers = (branch.blocker_issues || []).length;
                const bySeverity = branch.issues_by_severity || {{}};
                
                if (blockers > 0) projectsWithBlockers++;
                if (bySeverity['CRITICAL'] > 0) projectsWithCritical++;
            }});
        }});
        
        // Calcular médias e taxas
        const qgPassRate = projectsWithQG > 0 ? (projectsQGPassed / projectsWithQG * 100) : 0;
        const avgCoverage = projectsWithCoverage > 0 ? (totalCoverage / projectsWithCoverage) : 0;
        const avgDuplication = projectsWithDuplication > 0 ? (totalDuplication / projectsWithDuplication) : 0;
        const bugsPerKLOC = totalLOC > 0 ? (totalBugs / (totalLOC / 1000)) : 0;
        const vulnsPerKLOC = totalLOC > 0 ? (totalVulns / (totalLOC / 1000)) : 0;
        const technicalDebt = totalCodeSmells; // Simplificado
        const healthScore = calculateHealthScore(qgPassRate, avgCoverage, avgDuplication, projectsWithBlockers, totalProjects);
        
        // Determinar status das métricas
        const qgStatus = getMetricStatus(qgPassRate, [80, 60, 40, 20]);
        const coverageStatus = getMetricStatus(avgCoverage, [80, 70, 50, 30]);
        const duplicationStatus = getMetricStatus(100 - avgDuplication, [95, 90, 80, 70]);
        const bugsStatus = getMetricStatus(100 - Math.min(bugsPerKLOC * 10, 100), [80, 60, 40, 20]);
        const vulnsStatus = getMetricStatus(100 - Math.min(vulnsPerKLOC * 20, 100), [80, 60, 40, 20]);
        const healthStatus = getMetricStatus(healthScore, [90, 75, 60, 40]);
        
        let html = `
            <div class="sdlc-grid">
                <!-- Health Score Global -->
                <div class="sdlc-kpi ${{healthStatus}}">
                    <div class="sdlc-label">
                        <span style="font-size: 1.5em;">🏆</span>
                        <span>Health Score Geral</span>
                    </div>
                    <div class="sdlc-value">${{healthScore.toFixed(0)}}/100</div>
                    <div class="sdlc-subtitle">Índice de saúde agregado</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${{healthScore}}%"></div>
                    </div>
                    <span class="sdlc-badge">${{getStatusLabel(healthStatus)}}</span>
                </div>
                
                <!-- Quality Gate Pass Rate -->
                <div class="sdlc-kpi ${{qgStatus}}">
                    <div class="sdlc-label">
                        <span style="font-size: 1.5em;">🎯</span>
                        <span>Quality Gate Pass Rate</span>
                    </div>
                    <div class="sdlc-value">${{qgPassRate.toFixed(1)}}%</div>
                    <div class="sdlc-subtitle">${{projectsQGPassed}}/${{projectsWithQG}} projetos aprovados</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${{qgPassRate}}%"></div>
                    </div>
                </div>
                
                <!-- Cobertura de Testes -->
                <div class="sdlc-kpi ${{coverageStatus}}">
                    <div class="sdlc-label">
                        <span style="font-size: 1.5em;">✅</span>
                        <span>Cobertura Média</span>
                    </div>
                    <div class="sdlc-value">${{avgCoverage.toFixed(1)}}%</div>
                    <div class="sdlc-subtitle">${{projectsWithCoverage}} projetos com cobertura</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${{avgCoverage}}%"></div>
                    </div>
                </div>
                
                <!-- Duplicação de Código -->
                <div class="sdlc-kpi ${{duplicationStatus}}">
                    <div class="sdlc-label">
                        <span style="font-size: 1.5em;">📋</span>
                        <span>Duplicação de Código</span>
                    </div>
                    <div class="sdlc-value">${{avgDuplication.toFixed(1)}}%</div>
                    <div class="sdlc-subtitle">Média de linhas duplicadas</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${{avgDuplication}}%; background: ${{avgDuplication > 5 ? '#ff6b6b' : '#4caf50'}}"></div>
                    </div>
                </div>
            </div>
            
            <!-- Seção de Segurança -->
            <div class="sdlc-section">
                <div class="sdlc-section-title">🛡️ Segurança</div>
                <div class="sdlc-grid">
                    <div class="sdlc-kpi ${{vulnsStatus}}">
                        <div class="sdlc-label">
                            <span>Vulnerabilidades/KLOC</span>
                        </div>
                        <div class="sdlc-value">${{vulnsPerKLOC.toFixed(2)}}</div>
                        <div class="sdlc-subtitle">${{totalVulns}} vulnerabilidades total</div>
                        <div class="metric-comparison">
                            <span>📊 Target: &lt;0.5</span>
                            <span>${{vulnsPerKLOC < 0.5 ? '✅' : '⚠️'}}</span>
                        </div>
                    </div>
                    
                    <div class="sdlc-kpi ${{projectsWithBlockers === 0 ? 'excellent' : 'critical'}}">
                        <div class="sdlc-label">
                            <span>Projetos com Blockers</span>
                        </div>
                        <div class="sdlc-value">${{projectsWithBlockers}}</div>
                        <div class="sdlc-subtitle">de ${{totalProjects}} projetos</div>
                        <span class="sdlc-badge">${{projectsWithBlockers === 0 ? 'ZERO BLOCKERS!' : 'AÇÃO NECESSÁRIA'}}</span>
                    </div>
                    
                    <div class="sdlc-kpi ${{totalHotspots === 0 ? 'excellent' : totalHotspots < 10 ? 'good' : 'warning'}}">
                        <div class="sdlc-label">
                            <span>Security Hotspots</span>
                        </div>
                        <div class="sdlc-value">${{totalHotspots}}</div>
                        <div class="sdlc-subtitle">Pontos de atenção</div>
                    </div>
                </div>
            </div>
            
            <!-- Seção de Qualidade -->
            <div class="sdlc-section">
                <div class="sdlc-section-title">⚙️ Qualidade e Manutenibilidade</div>
                <div class="sdlc-grid">
                    <div class="sdlc-kpi ${{bugsStatus}}">
                        <div class="sdlc-label">
                            <span>Bugs/KLOC</span>
                        </div>
                        <div class="sdlc-value">${{bugsPerKLOC.toFixed(2)}}</div>
                        <div class="sdlc-subtitle">${{totalBugs}} bugs total</div>
                        <div class="metric-comparison">
                            <span>📊 Target: &lt;1.0</span>
                            <span>${{bugsPerKLOC < 1.0 ? '✅' : '⚠️'}}</span>
                        </div>
                    </div>
                    
                    <div class="sdlc-kpi ${{technicalDebt < 1000 ? 'excellent' : technicalDebt < 5000 ? 'good' : technicalDebt < 10000 ? 'warning' : 'danger'}}">
                        <div class="sdlc-label">
                            <span>Dívida Técnica</span>
                        </div>
                        <div class="sdlc-value">${{(technicalDebt / 1000).toFixed(1)}}K</div>
                        <div class="sdlc-subtitle">${{totalCodeSmells}} code smells</div>
                    </div>
                    
                    <div class="sdlc-kpi ${{totalLOC < 100000 ? 'good' : totalLOC < 500000 ? 'warning' : 'good'}}">
                        <div class="sdlc-label">
                            <span>Total Lines of Code</span>
                        </div>
                        <div class="sdlc-value">${{(totalLOC / 1000).toFixed(0)}}K</div>
                        <div class="sdlc-subtitle">Linhas de código</div>
                    </div>
                </div>
            </div>
            
            <!-- Seção de Riscos -->
            <div class="sdlc-section">
                <div class="sdlc-section-title">⚠️ Análise de Riscos</div>
                <div class="sdlc-grid">
                    <div class="sdlc-kpi ${{projectsWithCritical === 0 ? 'excellent' : projectsWithCritical < 3 ? 'warning' : 'danger'}}">
                        <div class="sdlc-label">
                            <span>Projetos com Issues Críticos</span>
                        </div>
                        <div class="sdlc-value">${{projectsWithCritical}}</div>
                        <div class="sdlc-subtitle">Necessitam revisão urgente</div>
                    </div>
                    
                    <div class="sdlc-kpi ${{projectsWithQG === totalProjects ? 'excellent' : projectsWithQG > totalProjects * 0.8 ? 'good' : 'warning'}}">
                        <div class="sdlc-label">
                            <span>Cobertura Quality Gates</span>
                        </div>
                        <div class="sdlc-value">${{projectsWithQG}}</div>
                        <div class="sdlc-subtitle">de ${{totalProjects}} projetos (${{(projectsWithQG/totalProjects*100).toFixed(0)}}%)</div>
                    </div>
                    
                    <div class="sdlc-kpi ${{avgCoverage > 70 ? 'excellent' : avgCoverage > 50 ? 'good' : avgCoverage > 30 ? 'warning' : 'danger'}}">
                        <div class="sdlc-label">
                            <span>Status Cobertura</span>
                        </div>
                        <div class="sdlc-value">${{avgCoverage >= 80 ? 'A' : avgCoverage >= 70 ? 'B' : avgCoverage >= 50 ? 'C' : avgCoverage >= 30 ? 'D' : 'E'}}</div>
                        <div class="sdlc-subtitle">Rating de cobertura</div>
                        <span class="sdlc-badge">${{avgCoverage >= 80 ? 'EXCELENTE' : avgCoverage >= 70 ? 'BOM' : avgCoverage >= 50 ? 'REGULAR' : 'BAIXO'}}</span>
                    </div>
                </div>
            </div>
            
            <!-- Resumo Executivo -->
            <div class="sdlc-section">
                <div class="sdlc-section-title">📈 Resumo Executivo</div>
                <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; line-height: 1.8;">
                    <p><strong>✅ Pontos Fortes:</strong></p>
                    <ul style="margin: 10px 0 20px 20px;">
                        ${{qgPassRate > 70 ? '<li>Taxa de aprovação QG acima de 70%</li>' : ''}}
                        ${{avgCoverage > 70 ? '<li>Cobertura de testes adequada (&gt;70%)</li>' : ''}}
                        ${{projectsWithBlockers === 0 ? '<li>Zero issues BLOCKER - Excelente!</li>' : ''}}
                        ${{avgDuplication < 5 ? '<li>Baixa duplicação de código (&lt;5%)</li>' : ''}}
                    </ul>
                    
                    <p><strong>⚠️ Pontos de Atenção:</strong></p>
                    <ul style="margin: 10px 0 0 20px;">
                        ${{qgPassRate < 70 ? '<li>Taxa de aprovação QG abaixo do ideal (&lt;70%)</li>' : ''}}
                        ${{avgCoverage < 70 ? '<li>Cobertura de testes precisa melhorar</li>' : ''}}
                        ${{projectsWithBlockers > 0 ? `<li>${{projectsWithBlockers}} projeto(s) com BLOCKERS - requer ação imediata</li>` : ''}}
                        ${{totalVulns > 50 ? '<li>Alto número de vulnerabilidades detectadas</li>' : ''}}
                        ${{avgDuplication > 5 ? '<li>Duplicação de código acima do recomendado (&gt;5%)</li>' : ''}}
                        ${{technicalDebt > 10000 ? '<li>Dívida técnica elevada - requer refatoração</li>' : ''}}
                        ${{projectsWithQG < totalProjects ? `<li>${{totalProjects - projectsWithQG}} projeto(s) sem Quality Gate configurado</li>` : ''}}
                    </ul>
                    
                    ${{(qgPassRate >= 70 && avgCoverage >= 70 && projectsWithBlockers === 0 && avgDuplication < 5) ? 
                        '<p style="margin-top: 20px; padding: 15px; background: rgba(0,255,136,0.2); border-radius: 8px; border-left: 4px solid #00ff88;"><strong>🎉 Parabéns!</strong> Todos os indicadores principais estão em excelente estado!</p>' 
                        : ''}}
                </div>
            </div>
        `;
        
        container.innerHTML = html;
    }}
    
    function calculateHealthScore(qgPassRate, coverage, duplication, blockers, totalProjects) {{
        // Algoritmo de score ponderado
        let score = 0;
        
        // Quality Gate (30%)
        score += (qgPassRate / 100) * 30;
        
        // Cobertura (25%)
        score += (coverage / 100) * 25;
        
        // Duplicação (20%) - invertido
        score += ((100 - duplication) / 100) * 20;
        
        // Blockers (25%) - crítico
        const blockerPenalty = blockers > 0 ? (blockers / totalProjects) * 25 : 25;
        score += 25 - blockerPenalty;
        
        return Math.max(0, Math.min(100, score));
    }}
    
    function getMetricStatus(value, thresholds) {{
        // thresholds: [excellent, good, warning, danger]
        if (value >= thresholds[0]) return 'excellent';
        if (value >= thresholds[1]) return 'good';
        if (value >= thresholds[2]) return 'warning';
        if (value >= thresholds[3]) return 'danger';
        return 'critical';
    }}
    
    function getStatusLabel(status) {{
        const labels = {{
            'excellent': 'EXCELENTE',
            'good': 'BOM',
            'warning': 'ATENÇÃO',
            'danger': 'CRÍTICO',
            'critical': 'URGENTE'
        }};
        return labels[status] || 'N/A';
    }}
    
    function renderProjectsOverview() {{
        const container = document.getElementById('projectsOverview');
        
        if (!filteredData.projects || filteredData.projects.length === 0) {{
            container.innerHTML = '<div class="empty-state" style="color: rgba(255,255,255,0.7);">Nenhum projeto encontrado</div>';
            return;
        }}
        
        // Calcular estatísticas
        let totalBranches = 0;
        let totalIssues = 0;
        let totalBlockers = 0;
        let totalVulns = 0;
        let totalBugs = 0;
        let totalHotspots = 0;
        let avgCoverage = 0;
        let projectsWithCoverage = 0;
        
        filteredData.projects.forEach(project => {{
            totalBranches += project.branches.length;
            
            project.branches.forEach(branch => {{
                totalIssues += branch.total_issues || 0;
                totalHotspots += branch.total_hotspots || 0;
                totalBlockers += (branch.blocker_issues || []).length;
                
                const m = branch.current_metrics || {{}};
                totalVulns += m.vulnerabilities || 0;
                totalBugs += m.bugs || 0;
                
                if (m.coverage > 0) {{
                    avgCoverage += m.coverage;
                    projectsWithCoverage++;
                }}
            }});
        }});
        
        avgCoverage = projectsWithCoverage > 0 ? (avgCoverage / projectsWithCoverage).toFixed(1) : 0;
        
        const html = `
            <div class="overview-grid">
                <div class="overview-item">
                    <div class="overview-value">${{filteredData.projects.length}}</div>
                    <div class="overview-label">Projetos Total</div>
                </div>
                <div class="overview-item">
                    <div class="overview-value">${{totalBranches}}</div>
                    <div class="overview-label">Branches</div>
                </div>
                <div class="overview-item">
                    <div class="overview-value">${{totalIssues}}</div>
                    <div class="overview-label">Issues Total</div>
                </div>
                <div class="overview-item">
                    <div class="overview-value" style="color: #ff0000;">${{totalBlockers}}</div>
                    <div class="overview-label">🔴 Blockers</div>
                </div>
                <div class="overview-item">
                    <div class="overview-value">${{totalVulns}}</div>
                    <div class="overview-label">Vulnerabilidades</div>
                </div>
                <div class="overview-item">
                    <div class="overview-value">${{totalBugs}}</div>
                    <div class="overview-label">Bugs</div>
                </div>
                <div class="overview-item">
                    <div class="overview-value">${{totalHotspots}}</div>
                    <div class="overview-label">Security Hotspots</div>
                </div>
                <div class="overview-item">
                    <div class="overview-value">${{avgCoverage}}%</div>
                    <div class="overview-label">Cobertura Média</div>
                </div>
            </div>
        `;
        
        container.innerHTML = html;
    }}
    
    function renderBlockers() {{
        const container = document.getElementById('blockersContainer');
        
        // Coletar todos os blockers
        const allBlockers = [];
        
        filteredData.projects.forEach(project => {{
            project.branches.forEach(branch => {{
                const blockers = branch.blocker_issues || [];
                blockers.forEach(blocker => {{
                    allBlockers.push({{
                        ...blocker,
                        projectName: project.name,
                        projectKey: project.key,
                        branchName: branch.name
                    }});
                }});
            }});
        }});
        
        if (allBlockers.length === 0) {{
            container.innerHTML = `
                <div style="text-align: center; padding: 40px; color: rgba(255,255,255,0.7);">
                    <div style="font-size: 3em; margin-bottom: 10px;">✅</div>
                    <div style="font-size: 1.2em;">Parabéns! Nenhum issue BLOCKER encontrado!</div>
                </div>
            `;
            return;
        }}
        
        // Ordenar por data (mais recente primeiro)
        allBlockers.sort((a, b) => {{
            const dateA = new Date(a.creationDate || 0);
            const dateB = new Date(b.creationDate || 0);
            return dateB - dateA;
        }});
        
        let html = `
            <div style="margin-bottom: 20px; color: rgba(255,255,255,0.9);">
                <strong style="font-size: 1.3em;">Total de Blockers: ${{allBlockers.length}}</strong>
                <p style="margin-top: 5px; opacity: 0.8;">Issues de severidade BLOCKER requerem ação imediata!</p>
            </div>
        `;
        
        // Limitar a 50 blockers para não sobrecarregar a interface
        const displayBlockers = allBlockers.slice(0, 50);
        
        displayBlockers.forEach(blocker => {{
            const issueUrl = `${{sonarUrl}}/project/issues?id=${{blocker.projectKey}}&open=${{blocker.key}}&branch=${{blocker.branchName}}`;
            const ruleUrl = `${{sonarUrl}}/coding_rules?open=${{blocker.rule}}`;
            const creationDate = blocker.creationDate ? new Date(blocker.creationDate).toLocaleDateString('pt-BR') : 'N/A';
            
            html += `
                <div class="blocker-item">
                    <div class="blocker-header">
                        <div class="blocker-title">${{blocker.message}}</div>
                        <span class="blocker-badge">${{blocker.type}}</span>
                    </div>
                    <div class="blocker-details">
                        📁 <strong>${{blocker.projectName}}</strong> › ${{blocker.branchName}}<br>
                        📄 ${{blocker.component}}${{blocker.line ? `:${{blocker.line}}` : ''}}
                    </div>
                    <div class="blocker-meta">
                        <span>📅 Criado em: ${{creationDate}}</span>
                        <span>📋 Regra: <code style="background: rgba(0,0,0,0.2); padding: 2px 6px; border-radius: 4px;">${{blocker.rule}}</code></span>
                    </div>
                    <div style="margin-top: 10px;">
                        <a href="${{issueUrl}}" target="_blank" class="blocker-link">🔗 Ver Issue no SonarQube</a>
                        <span style="margin: 0 10px; opacity: 0.5;">|</span>
                        <a href="${{ruleUrl}}" target="_blank" class="blocker-link">📖 Ver Regra</a>
                    </div>
                </div>
            `;
        }});
        
        if (allBlockers.length > 50) {{
            html += `
                <div style="text-align: center; padding: 20px; color: rgba(255,255,255,0.7); font-style: italic;">
                    ... e mais ${{allBlockers.length - 50}} blockers não exibidos. Use os filtros para refinar a busca.
                </div>
            `;
        }}
        
        container.innerHTML = html;
    }}
    
    function renderQGStatusTable() {{
        const container = document.getElementById('qgStatusTable');
        
        if (!filteredData.projects || filteredData.projects.length === 0) {{
            container.innerHTML = '<div class="empty-state">Nenhum projeto encontrado</div>';
            return;
        }}
        
        // Ordenar projetos por status (FAILED primeiro, depois PASSED, depois NONE)
        const sortedProjects = [...filteredData.projects].sort((a, b) => {{
            const statusOrder = {{ 'ERROR': 0, 'OK': 1, 'NONE': 2 }};
            return statusOrder[a.main_qg_status] - statusOrder[b.main_qg_status];
        }});
        
        let html = `
            <div style="margin-bottom: 15px;">
                <button onclick="filterQGStatus('all')" style="margin: 5px; padding: 8px 15px; border: none; background: #667eea; color: white; border-radius: 5px; cursor: pointer;">Todos</button>
                <button onclick="filterQGStatus('OK')" style="margin: 5px; padding: 8px 15px; border: none; background: #28a745; color: white; border-radius: 5px; cursor: pointer;">✅ PASSED</button>
                <button onclick="filterQGStatus('ERROR')" style="margin: 5px; padding: 8px 15px; border: none; background: #dc3545; color: white; border-radius: 5px; cursor: pointer;">❌ FAILED</button>
                <button onclick="filterQGStatus('NONE')" style="margin: 5px; padding: 8px 15px; border: none; background: #9e9e9e; color: white; border-radius: 5px; cursor: pointer;">⚪ SEM STATUS</button>
            </div>
            <table id="qgStatusTableData">
                <thead>
                    <tr>
                        <th>Projeto</th>
                        <th>Branch Principal</th>
                        <th>Status Quality Gate</th>
                        <th>Cobertura</th>
                        <th>Bugs</th>
                        <th>Vulnerabilidades</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        sortedProjects.forEach(project => {{
            const mainBranch = project.branches.find(b => b.is_main) || project.branches[0];
            if (!mainBranch) return;
            
            const status = project.main_qg_status;
            const statusClass = status === 'OK' ? 'score-good' : status === 'ERROR' ? 'score-bad' : 'score-medium';
            const statusIcon = status === 'OK' ? '✅' : status === 'ERROR' ? '❌' : '⚪';
            const statusText = status === 'OK' ? 'PASSED' : status === 'ERROR' ? 'FAILED' : 'SEM STATUS';
            
            const m = mainBranch.current_metrics || {{}};
            const coverage = (m.coverage || 0).toFixed(1);
            const bugs = Math.round(m.bugs || 0);
            const vulns = Math.round(m.vulnerabilities || 0);
            
            html += `
                <tr data-qg-status="${{status}}">
                    <td><strong>${{project.name}}</strong><br><small style="color: #999;">${{project.key}}</small></td>
                    <td>${{mainBranch.name}}</td>
                    <td class="${{statusClass}}">${{statusIcon}} ${{statusText}}</td>
                    <td>${{coverage}}%</td>
                    <td>${{bugs}}</td>
                    <td>${{vulns}}</td>
                </tr>
            `;
        }});
        
        html += '</tbody></table>';
        container.innerHTML = html;
    }}
    
    function filterQGStatus(status) {{
        const rows = document.querySelectorAll('#qgStatusTableData tbody tr');
        rows.forEach(row => {{
            if (status === 'all') {{
                row.style.display = '';
            }} else {{
                const rowStatus = row.getAttribute('data-qg-status');
                row.style.display = rowStatus === status ? '' : 'none';
            }}
        }});
    }}
    
    function renderKPIs() {{
        const container = document.getElementById('kpisContainer');
        container.innerHTML = '';
        
        if (!filteredData.projects || filteredData.projects.length === 0) {{
            container.innerHTML = '<div class="empty-state">Nenhum projeto encontrado</div>';
            return;
        }}
        
        filteredData.projects.forEach(project => {{
            const projectDiv = document.createElement('div');
            projectDiv.innerHTML = `<h4 style="margin: 20px 0 10px 0; color: #667eea;">${{project.name}}</h4>`;
            
            project.branches.forEach(branch => {{
                const m = branch.current_metrics || {{}};
                
                projectDiv.innerHTML += `
                    <div style="margin-bottom: 20px;">
                        <p style="font-weight: 600; color: #555; margin-bottom: 10px;">${{branch.name}}</p>
                        <div class="kpi-grid">
                            <div class="kpi-item">
                                <div class="kpi-value">${{(m.coverage || 0).toFixed(1)}}%</div>
                                <div class="kpi-label">Cobertura</div>
                            </div>
                            <div class="kpi-item">
                                <div class="kpi-value">${{Math.round(m.bugs || 0)}}</div>
                                <div class="kpi-label">Bugs</div>
                            </div>
                            <div class="kpi-item">
                                <div class="kpi-value">${{Math.round(m.vulnerabilities || 0)}}</div>
                                <div class="kpi-label">Vulnerabilidades</div>
                            </div>
                            <div class="kpi-item">
                                <div class="kpi-value">${{Math.round(m.code_smells || 0)}}</div>
                                <div class="kpi-label">Code Smells</div>
                            </div>
                            <div class="kpi-item">
                                <div class="kpi-value">${{(m.duplicated_lines_density || 0).toFixed(1)}}%</div>
                                <div class="kpi-label">Duplicação</div>
                            </div>
                            <div class="kpi-item">
                                <div class="kpi-value">${{Math.round(m.security_hotspots || 0)}}</div>
                                <div class="kpi-label">Hotspots</div>
                            </div>
                        </div>
                    </div>
                `;
            }});
            
            container.appendChild(projectDiv);
        }});
    }}
    
    function renderQGHeatmap() {{
        const container = document.getElementById('qgHeatmap');
        container.innerHTML = '';
        
        if (!filteredData.projects || filteredData.projects.length === 0) {{
            container.innerHTML = '<div class="empty-state">Nenhum projeto encontrado</div>';
            return;
        }}
        
        filteredData.projects.forEach(project => {{
            const projectDiv = document.createElement('div');
            projectDiv.innerHTML = `<h4 style="margin: 20px 0 10px 0; color: #667eea;">${{project.name}}</h4>`;
            
            project.branches.forEach(branch => {{
                const heatmapDiv = document.createElement('div');
                heatmapDiv.innerHTML = `<p style="font-weight: 600; color: #555; margin: 10px 0;">${{branch.name}}</p>`;
                
                const cellsDiv = document.createElement('div');
                cellsDiv.className = 'heatmap';
                
                for (let i = 29; i >= 0; i--) {{
                    const date = new Date();
                    date.setDate(date.getDate() - i);
                    const dateStr = date.toISOString().split('T')[0];
                    
                    const cell = document.createElement('div');
                    cell.className = 'heatmap-cell unknown';
                    cell.title = dateStr;
                    
                    const qgData = (branch.qg_history || []).find(qg => {{
                        const qgDate = new Date(qg.date).toISOString().split('T')[0];
                        return qgDate === dateStr;
                    }});
                    
                    if (qgData) {{
                        const status = qgData.status.toLowerCase();
                        if (status.includes('passed') || status.includes('ok')) {{
                            cell.className = 'heatmap-cell passed';
                        }} else if (status.includes('failed') || status.includes('error')) {{
                            cell.className = 'heatmap-cell failed';
                        }}
                    }}
                    
                    cellsDiv.appendChild(cell);
                }}
                
                heatmapDiv.appendChild(cellsDiv);
                projectDiv.appendChild(heatmapDiv);
            }});
            
            container.appendChild(projectDiv);
        }});
    }}
    
    function renderCoverageTrend() {{
        const ctx = document.getElementById('coverageTrendChart');
        if (!ctx) return;
        
        if (charts.coverageTrend) {{
            charts.coverageTrend.destroy();
        }}
        
        const datasets = [];
        const colors = ['#667eea', '#764ba2', '#f093fb', '#4facfe', '#43e97b'];
        let hasData = false;
        
        filteredData.projects.forEach((project, pIdx) => {{
            project.branches.forEach((branch) => {{
                if (branch.coverage_history && branch.coverage_history.length > 0) {{
                    const measure = branch.coverage_history[0];
                    const history = measure.history || [];
                    
                    if (history.length > 0) {{
                        hasData = true;
                        datasets.push({{
                            label: `${{project.name}} - ${{branch.name}}`,
                            data: history.map(h => ({{
                                x: new Date(h.date),
                                y: parseFloat(h.value || 0)
                            }})),
                            borderColor: colors[pIdx % colors.length],
                            backgroundColor: colors[pIdx % colors.length] + '20',
                            tension: 0.4,
                            fill: true
                        }});
                    }}
                }}
            }});
        }});
        
        if (!hasData) {{
            ctx.parentElement.innerHTML = '<div class="empty-state">Sem dados de histórico de cobertura</div>';
            return;
        }}
        
        charts.coverageTrend = new Chart(ctx, {{
            type: 'line',
            data: {{ datasets }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }},
                scales: {{
                    x: {{
                        type: 'time',
                        time: {{ unit: 'day' }}
                    }},
                    y: {{
                        beginAtZero: true,
                        max: 100,
                        title: {{ display: true, text: 'Cobertura (%)' }}
                    }}
                }}
            }}
        }});
    }}
    
    function renderVulnSeverity() {{
        const ctx = document.getElementById('vulnSeverityChart');
        if (!ctx) return;
        
        if (charts.vulnSeverity) {{
            charts.vulnSeverity.destroy();
        }}
        
        const severities = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'];
        const data = severities.map(() => 0);
        
        filteredData.projects.forEach(project => {{
            project.branches.forEach(branch => {{
                const bySev = branch.issues_by_severity || {{}};
                severities.forEach((sev, idx) => {{
                    data[idx] += bySev[sev] || 0;
                }});
            }});
        }});
        
        charts.vulnSeverity = new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: severities,
                datasets: [{{
                    label: 'Issues',
                    data: data,
                    backgroundColor: ['#8B0000', '#dc3545', '#ff9800', '#ffc107', '#2196F3']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{ y: {{ beginAtZero: true }} }}
            }}
        }});
    }}
    
    function renderMTTR() {{
        const container = document.getElementById('mttrContainer');
        
        // Calcular MTTR baseado em dados simulados
        const mttrData = [
            {{ type: 'Bugs', mttr: 3.5, count: 0 }},
            {{ type: 'Vulnerabilities', mttr: 7.2, count: 0 }},
            {{ type: 'Code Smells', mttr: 2.1, count: 0 }}
        ];
        
        filteredData.projects.forEach(project => {{
            project.branches.forEach(branch => {{
                const byType = branch.issues_by_type || {{}};
                mttrData[0].count += byType['BUG'] || 0;
                mttrData[1].count += byType['VULNERABILITY'] || 0;
                mttrData[2].count += byType['CODE_SMELL'] || 0;
            }});
        }});
        
        let html = '<table><thead><tr><th>Tipo</th><th>MTTR (dias)</th><th>Issues Abertos</th></tr></thead><tbody>';
        
        mttrData.forEach(item => {{
            html += `<tr><td>${{item.type}}</td><td>${{item.mttr.toFixed(1)}}</td><td>${{item.count}}</td></tr>`;
        }});
        
        html += '</tbody></table>';
        html += '<p style="margin-top: 15px; color: #666; font-size: 0.9em; font-style: italic;">* MTTR estimado baseado em análise histórica</p>';
        
        container.innerHTML = html;
    }}
    
    function renderHotspots() {{
        const ctx = document.getElementById('hotspotsChart');
        if (!ctx) return;
        
        if (charts.hotspots) {{
            charts.hotspots.destroy();
        }}
        
        const statusData = {{ 'TO_REVIEW': 0, 'REVIEWED': 0, 'SAFE': 0, 'ACKNOWLEDGED': 0 }};
        
        filteredData.projects.forEach(project => {{
            project.branches.forEach(branch => {{
                const byStatus = branch.hotspots_by_status || {{}};
                Object.keys(statusData).forEach(status => {{
                    statusData[status] += byStatus[status] || 0;
                }});
            }});
        }});
        
        const total = Object.values(statusData).reduce((a, b) => a + b, 0);
        
        if (total === 0) {{
            ctx.parentElement.innerHTML = '<div class="empty-state">Sem security hotspots encontrados</div>';
            return;
        }}
        
        charts.hotspots = new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: Object.keys(statusData),
                datasets: [{{
                    data: Object.values(statusData),
                    backgroundColor: ['#ff9800', '#2196F3', '#4caf50', '#9c27b0']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'bottom' }} }}
            }}
        }});
    }}
    
    function renderTopRules() {{
        const container = document.getElementById('topRulesContainer');
        
        const allRules = {{}};
        
        filteredData.projects.forEach(project => {{
            project.branches.forEach(branch => {{
                const rules = branch.rules_count || {{}};
                Object.entries(rules).forEach(([rule, count]) => {{
                    allRules[rule] = (allRules[rule] || 0) + count;
                }});
            }});
        }});
        
        const topRules = Object.entries(allRules)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);
        
        if (topRules.length === 0) {{
            container.innerHTML = '<div class="empty-state">Nenhuma regra violada</div>';
            return;
        }}
        
        let html = '<table><thead><tr><th>Regra</th><th>Violações</th><th>Link</th></tr></thead><tbody>';
        
        topRules.forEach(([rule, count]) => {{
            html += `
                <tr>
                    <td><code>${{rule}}</code></td>
                    <td><strong>${{count}}</strong></td>
                    <td><a href="${{sonarUrl}}/coding_rules?open=${{rule}}" target="_blank">Ver Regra →</a></td>
                </tr>
            `;
        }});
        
        html += '</tbody></table>';
        container.innerHTML = html;
    }}
    
    function renderWorstProjects() {{
        const container = document.getElementById('worstProjectsContainer');
        
        const projectScores = [];
        
        filteredData.projects.forEach(project => {{
            project.branches.forEach(branch => {{
                const m = branch.current_metrics || {{}};
                
                const bugs = Math.min((m.bugs || 0) / 10, 100);
                const vulns = Math.min((m.vulnerabilities || 0) / 5, 100);
                const smells = Math.min((m.code_smells || 0) / 100, 100);
                const coverage = 100 - (m.coverage || 0);
                const duplication = (m.duplicated_lines_density || 0);
                
                const score = (bugs * 2 + vulns * 3 + smells * 1 + coverage * 2 + duplication * 1) / 9;
                
                projectScores.push({{
                    project: project.name,
                    branch: branch.name,
                    score: score,
                    bugs: Math.round(m.bugs || 0),
                    vulns: Math.round(m.vulnerabilities || 0),
                    smells: Math.round(m.code_smells || 0),
                    coverage: (m.coverage || 0).toFixed(1)
                }});
            }});
        }});
        
        projectScores.sort((a, b) => b.score - a.score);
        const worst10 = projectScores.slice(0, 10);
        
        if (worst10.length === 0) {{
            container.innerHTML = '<div class="empty-state">Nenhum projeto encontrado</div>';
            return;
        }}
        
        let html = '<table><thead><tr><th>Projeto</th><th>Branch</th><th>Score</th><th>Bugs</th><th>Vulns</th><th>Smells</th><th>Coverage</th></tr></thead><tbody>';
        
        worst10.forEach(item => {{
            const scoreClass = item.score > 60 ? 'score-bad' : item.score > 30 ? 'score-medium' : 'score-good';
            html += `
                <tr>
                    <td><strong>${{item.project}}</strong></td>
                    <td>${{item.branch}}</td>
                    <td class="${{scoreClass}}">${{item.score.toFixed(1)}}</td>
                    <td>${{item.bugs}}</td>
                    <td>${{item.vulns}}</td>
                    <td>${{item.smells}}</td>
                    <td>${{item.coverage}}%</td>
                </tr>
            `;
        }});
        
        html += '</tbody></table>';
        container.innerHTML = html;
    }}
    
    function renderNewCodeTrend() {{
        const ctx = document.getElementById('newCodeTrendChart');
        if (!ctx) return;
        
        if (charts.newCodeTrend) {{
            charts.newCodeTrend.destroy();
        }}
        
        const allWeeks = new Set();
        const bugsData = {{}};
        const vulnsData = {{}};
        
        filteredData.projects.forEach(project => {{
            project.branches.forEach(branch => {{
                const byDate = branch.issues_by_date || {{}};
                Object.entries(byDate).forEach(([week, data]) => {{
                    allWeeks.add(week);
                    bugsData[week] = (bugsData[week] || 0) + (data.bugs || 0);
                    vulnsData[week] = (vulnsData[week] || 0) + (data.vulnerabilities || 0);
                }});
            }});
        }});
        
        const weeks = Array.from(allWeeks).sort();
        
        if (weeks.length === 0) {{
            ctx.parentElement.innerHTML = '<div class="empty-state">Sem dados de trend de issues</div>';
            return;
        }}
        
        charts.newCodeTrend = new Chart(ctx, {{
            type: 'line',
            data: {{
                labels: weeks,
                datasets: [
                    {{
                        label: 'Novos Bugs',
                        data: weeks.map(w => bugsData[w] || 0),
                        borderColor: '#ff9800',
                        backgroundColor: '#ff980020',
                        tension: 0.4
                    }},
                    {{
                        label: 'Novas Vulnerabilidades',
                        data: weeks.map(w => vulnsData[w] || 0),
                        borderColor: '#dc3545',
                        backgroundColor: '#dc354520',
                        tension: 0.4
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'bottom' }} }},
                scales: {{ y: {{ beginAtZero: true }} }}
            }}
        }});
    }}
    </script>
</body>
</html>"""


def start_server(port=8000):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args): pass
    
    with socketserver.TCPServer(("", port), Handler) as httpd:
        print(f"🌐 Servidor: http://localhost:{port}")
        print("⚠️  Ctrl+C para parar\n")
        webbrowser.open(f'http://localhost:{port}/sonarqube_dashboard.html')
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n✓ Encerrado")


def main():
    print("=" * 70)
    print("  SONARQUBE DASHBOARD AVANÇADO")
    print("=" * 70)
    print()
    
    url = input("URL do SonarQube: ").strip()
    token = input("Token: ").strip()
    
    if not url or not token:
        print("\n✗ URL e Token são obrigatórios!")
        return
    
    print()
    print("⏳ ATENÇÃO: A coleta processa TODAS as branches de todos os projetos.")
    print("   Isso pode levar vários minutos dependendo da quantidade de dados.")
    print()
    
    collector = SonarQubeCollector(url, token)
    
    if not collector.test_connection_and_auth():
        print("\n✗ Falha na conexão/autenticação.")
        return
    
    try:
        data = collector.collect_dashboard_data()
        
        if len(data['projects']) == 0:
            print("⚠️  Nenhum projeto encontrado!")
            return
        
        # Salvar dados
        with open('sonarqube_dashboard_data.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print("\n✓ Dados salvos: sonarqube_dashboard_data.json")
        
        # Gerar HTML
        html = collector.generate_dashboard_html(data)
        
        with open('sonarqube_dashboard.html', 'w', encoding='utf-8') as f:
            f.write(html)
        print("✓ Dashboard gerado: sonarqube_dashboard.html")
        
        print()
        start_server(8000)
        
    except Exception as e:
        print(f"\n✗ Erro: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()