"""
JSHunter — AST Visitor
Navegador de arvore sintatica JavaScript (Esprima)
Detecta vulnerabilidades via analise contextual
"""


class ASTVisitor:
    """Classe auxiliar para navegar na arvore sintatica do JavaScript"""

    def __init__(self):
        self.findings = {
            'credentials': [],
            'xss': [],
            'frameworks': set(),
            'dangerous_functions': [],
        }
        self.sensitive_vars = {
            'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'auth',
            'api_key', 'access_token', 'refresh_token', 'private_key',
            'client_secret', 'session_token', 'bearer', 'authorization',
        }
        self.sinks = {'eval', 'setTimeout', 'setInterval', 'execScript', 'Function'}
        self.dom_sinks = {'innerHTML', 'outerHTML', 'document.write', 'document.writeln'}

    def visit(self, node):
        """Visita recursiva aos nos"""
        method_name = 'visit_' + node.type
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        """Navega pelos filhos do no atual"""
        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self.visit(item)
            elif hasattr(value, 'type'):
                self.visit(value)

    def _get_line(self, node):
        """Extrai numero da linha do no"""
        return node.loc.start.line if hasattr(node, 'loc') and node.loc else 0

    def visit_VariableDeclarator(self, node):
        """Analisa declaracoes: const password = '123';"""
        if node.id.type == 'Identifier' and node.init:
            var_name = node.id.name.lower()
            if any(s in var_name for s in self.sensitive_vars):
                if node.init.type == 'Literal' and isinstance(node.init.value, str):
                    if len(node.init.value) > 3:
                        self.findings['credentials'].append({
                            'type': 'Hardcoded Credential (AST)',
                            'match': f'{node.id.name} = "{node.init.value[:20]}..."',
                            'line': self._get_line(node),
                            'severity': 'critical',
                            'confidence': 'High',
                        })
        self.generic_visit(node)

    def visit_AssignmentExpression(self, node):
        """Analisa atribuicoes: element.innerHTML = userInput;"""
        if node.left.type == 'MemberExpression' and node.left.property.type == 'Identifier':
            prop_name = node.left.property.name

            # DOM XSS Sinks
            if prop_name in self.dom_sinks:
                is_safe = (node.right.type == 'Literal')
                if not is_safe:
                    self.findings['xss'].append({
                        'type': f'DOM XSS Sink ({prop_name})',
                        'match': f'Assignment to {prop_name} with dynamic content',
                        'line': self._get_line(node),
                        'severity': 'high',
                    })

            # postMessage handler
            if prop_name == 'onmessage':
                self.findings['xss'].append({
                    'type': 'postMessage Handler',
                    'match': 'onmessage handler detected — verify origin validation',
                    'line': self._get_line(node),
                    'severity': 'medium',
                })

        self.generic_visit(node)

    def visit_CallExpression(self, node):
        """Analisa chamadas de funcao: eval(code), React.createElement(...)"""
        # 1. Execution sinks
        if node.callee.type == 'Identifier':
            func_name = node.callee.name
            if func_name in self.sinks:
                if node.arguments and node.arguments[0].type != 'Literal':
                    self.findings['xss'].append({
                        'type': f'Execution Sink ({func_name})',
                        'match': f'Call to {func_name} with dynamic argument',
                        'line': self._get_line(node),
                        'severity': 'critical',
                    })

            # postMessage
            if func_name == 'postMessage':
                self.findings['xss'].append({
                    'type': 'postMessage Usage',
                    'match': 'postMessage() called — check for origin validation',
                    'line': self._get_line(node),
                    'severity': 'medium',
                })

            # Framework detection
            if 'vue' in func_name.lower():
                self.findings['frameworks'].add('Vue.js')
            if 'angular' in func_name.lower():
                self.findings['frameworks'].add('Angular')

        # 2. MemberExpression calls
        if node.callee.type == 'MemberExpression':
            if hasattr(node.callee.object, 'name') and node.callee.object.name == 'React':
                self.findings['frameworks'].add('React')

            # window.open with dynamic URL
            if (hasattr(node.callee.object, 'name') and
                node.callee.object.name == 'window' and
                hasattr(node.callee.property, 'name') and
                node.callee.property.name == 'open'):
                if node.arguments and node.arguments[0].type != 'Literal':
                    self.findings['xss'].append({
                        'type': 'Open Redirect Risk',
                        'match': 'window.open() with dynamic URL',
                        'line': self._get_line(node),
                        'severity': 'medium',
                    })

            # document.cookie access
            if (hasattr(node.callee.object, 'type') and
                node.callee.object.type == 'MemberExpression'):
                try:
                    obj = node.callee.object
                    if (hasattr(obj.object, 'name') and obj.object.name == 'document' and
                        hasattr(obj.property, 'name') and obj.property.name == 'cookie'):
                        self.findings['dangerous_functions'].append({
                            'type': 'Cookie Manipulation',
                            'match': 'document.cookie access detected',
                            'line': self._get_line(node),
                            'severity': 'medium',
                        })
                except AttributeError:
                    pass

        self.generic_visit(node)

    def visit_Property(self, node):
        """Analisa propriedades de objetos"""
        if node.key.type == 'Identifier' and node.key.name == 'dangerouslySetInnerHTML':
            self.findings['xss'].append({
                'type': 'React Dangerous Sink',
                'match': 'dangerouslySetInnerHTML usage detected',
                'line': self._get_line(node),
                'severity': 'high',
            })
            self.findings['frameworks'].add('React')
        self.generic_visit(node)

    def visit_NewExpression(self, node):
        """Detect new Function() constructor"""
        if node.callee.type == 'Identifier' and node.callee.name == 'Function':
            if node.arguments:
                self.findings['xss'].append({
                    'type': 'Dynamic Function Constructor',
                    'match': 'new Function() with dynamic code — equivalent to eval()',
                    'line': self._get_line(node),
                    'severity': 'critical',
                })
        self.generic_visit(node)
