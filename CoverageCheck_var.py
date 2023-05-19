import networkx as nx
from clingo import ast
from clingo.control import Control
from clingo.ast import ASTType, ProgramBuilder, parse_files, parse_string
from dependencygraph_tools import build_dependency_graph, find_loops, find_sccs


class CoverageCheck():
    def __init__(self, args):
        self.posRCov = set()
        self.negRCov = set()
        self.posDCov = set()
        self.negDCov = set()
        self.posLCov = set()
        self.negLCov = set()
        self.posCCov = set()
        self.negCCov = set()
        self.pCov = set()
        self.numRules = 0
        self.numDef = 0
        self.numTestcases = 0
        self.rules = []
        self.constraintcounter = 0
        self.model = set()
        self.atoms = dict()
        self.loops = set()
        self.sccs = []
        self.graph = nx.DiGraph()
        self.args = args
        self.ctl = Control(["0"], message_limit=0)
    

    def on_model(self, model):
        self.model = set([atm.name for atm in model.symbols(atoms=True) if (atm.name.startswith("_") or atm.name.startswith("-_"))])
        # print(self.model)


    def add_rules(self):
        with ProgramBuilder(self.ctl) as bld:
            for idx, rule in enumerate(self.rules):
                if str(rule.head) != "#false":
                    pos = ast.Position('<string>', 1, 1)
                    loc = ast.Location(pos, pos)
                    fun = ast.Function(loc, '_r{}'.format(idx), [], False)
                    fun2 = ast.Function(loc, '-_r{}'.format(idx), [], False)
                    atm = ast.SymbolicAtom(fun)
                    atm2 = ast.SymbolicAtom(fun2)
                    lit = ast.Literal(loc, ast.Sign.NoSign, atm)
                    lit2 = ast.Literal(loc, ast.Sign.NoSign, atm2)
                    bld.add(ast.Rule(loc, lit, rule.body))
                    bld.add(ast.Rule(loc, lit2, [ast.Literal(loc, ast.Sign.Negation, atm)]))
                    # print(ast.Rule(loc, lit, rule.body))
                    # print(ast.Rule(loc, lit2, [ast.Literal(loc, ast.Sign.Negation, atm)]))

    def add_definitions(self):
        with ProgramBuilder(self.ctl) as bld:
            for value in self.atoms.values():
                if value[2]: 
                    pos = ast.Position('<string>', 1, 1)
                    loc = ast.Location(pos, pos)
                    fun = ast.Function(loc, '_d{}'.format(value[0][0]), [], False)
                    atm = ast.SymbolicAtom(fun)
                    head = ast.Literal(loc, ast.Sign.NoSign, atm)                    
                    fun2 = ast.Function(loc, '-_d{}'.format(value[0][0]), [], False)
                    atm2 = ast.SymbolicAtom(fun2)
                    head2 = ast.Literal(loc, ast.Sign.NoSign, atm2)
                    bld.add(ast.Rule(loc, head2, [ast.Literal(loc, ast.Sign.Negation, atm)]))
                for idx in value[2]:
                    fun3 = ast.Function(loc, '_r{}'.format(idx), [], False)
                    atm3 = ast.SymbolicAtom(fun3)
                    body = ast.Literal(loc, ast.Sign.NoSign, atm3)
                    bld.add(ast.Rule(loc, head, [body]))
                    #print(ast.Rule(loc, head2, [ast.Literal(loc, ast.Sign.Negation, atm)]))

    def add_loops(self):
        with ProgramBuilder(self.ctl) as bld:
            for idx, loop in enumerate(self.loops):
                body = []
                pos = ast.Position('<string>', 1, 1)
                loc = ast.Location(pos, pos)
                fun = ast.Function(loc, '_l{}'.format(idx), [], False)
                fun2 = ast.Function(loc, '-_l{}'.format(idx), [], False)
                atm = ast.SymbolicAtom(fun)
                atm2 = ast.SymbolicAtom(fun2)
                head = ast.Literal(loc, ast.Sign.NoSign, atm)
                head2 = ast.Literal(loc, ast.Sign.NoSign, atm2)
                for key in loop:
                    if self.atoms[key][2]:
                        fun3 = ast.Function(loc, '_d{}'.format(self.atoms[key][0][0]), [], False)
                        atm3 = ast.SymbolicAtom(fun3)
                        lit = ast.Literal(loc, ast.Sign.NoSign, atm3)
                        body.append(lit)
                if body:
                    bld.add(ast.Rule(loc, head, body))
                    bld.add(ast.Rule(loc, head2, [ast.Literal(loc, ast.Sign.Negation, atm)]))
                # print(ast.Rule(loc, head2, [ast.Literal(loc, ast.Sign.Negation, atm)]))
                # print(ast.Rule(loc, head, body))
            
    def add_sccs(self):
        with ProgramBuilder(self.ctl) as bld:
            for idx, scc in enumerate(self.sccs):
                body = []
                nbody = []
                pos = ast.Position('<string>', 1, 1)
                loc = ast.Location(pos, pos)
                fun = ast.Function(loc, '_c{}'.format(idx), [], False)
                fun2 = ast.Function(loc, '-_c{}'.format(idx), [], False)
                atm = ast.SymbolicAtom(fun)
                atm2 = ast.SymbolicAtom(fun2)
                head = ast.Literal(loc, ast.Sign.NoSign, atm)
                nhead = ast.Literal(loc, ast.Sign.NoSign, atm2)
                for key in scc:
                    if self.atoms[key][2]:
                        fun = ast.Function(loc, '_d{}'.format(self.atoms[key][0][0]), [], False)
                        atm = ast.SymbolicAtom(fun)
                        lit = ast.Literal(loc, ast.Sign.NoSign, atm)
                        lit2 = ast.Literal(loc, ast.Sign.Negation, atm)
                        body.append(lit)
                        nbody.append(lit2)
                if body:
                    bld.add(ast.Rule(loc, head, body))
                    bld.add(ast.Rule(loc, nhead, nbody))
                # print(ast.Rule(loc, head, body))
                # print(ast.Rule(loc, nhead, nbody))

    def add_input(self, node):
        if not node.ast_type == ASTType.Program:
            pos = ast.Position('<string>', 1, 1)
            loc = ast.Location(pos, pos)
            fun = ast.Function(loc, '_i{}'.format(self.numTestcases), [], False)
            atm = ast.SymbolicAtom(fun)
            body = ast.Literal(loc, ast.Sign.NoSign, atm)
            with ProgramBuilder(self.ctl) as bld:
                bld.add(ast.Rule(loc, node.head, [body]))
                # print(ast.Rule(loc, node.head, [body]))

    def add_program(self):
        if self.args.rule or self.args.definition or self.args.loop or self.args.component:
            for file in self.args.testcases:
                parse_files([file], self.add_input)
                self.numTestcases += 1
            with ProgramBuilder(self.ctl) as bld:
                str = "{ " + " ".join([f"_i{num};" for num in range(self.numTestcases)])[:-1] + " } = 1."
                parse_string(str, bld.add)
                parse_files(self.args.files, lambda stm: bld.add(self.gather_info(stm)))
                self.numRules = len(self.rules) + self.constraintcounter
                # print(str)

        
    def gather_info(self, node, prog=False):
        if node.ast_type == ASTType.Rule:
            self.rules.append(node)
            if not prog:
                ### Head ###
                if node.head.ast_type == ASTType.Aggregate or node.head.ast_type == ASTType.Disjunction:
                    for elem in node.head.elements:
                        if elem.literal.atom.ast_type == ASTType.SymbolicAtom:
                            if elem.literal.atom.symbol.ast_type == ASTType.Pool:
                                key = (elem.literal.atom.symbol.arguments[0].name, len(elem.literal.atom.symbol.arguments[0].arguments))
                            else:
                                key = (elem.literal.atom.symbol.name, len(elem.literal.atom.symbol.arguments))
                            if key not in self.atoms.keys():
                                if elem.literal.sign == 0:
                                    self.atoms[key] = [[self.numDef],[elem.literal.location],[len(self.rules)-1]]
                                    self.numDef += 1
                                else:
                                    self.atoms[key] = [[self.numDef], [elem.literal.location],[]]
                                    self.numDef += 1
                            else:
                                if elem.literal.sign == 0:
                                    if not self.atoms[key][2]:
                                        self.atoms[key][1] = []
                                    self.atoms[key][1].append(elem.literal.location)
                                    self.atoms[key][2].append(len(self.rules)-1)
                        for lit in elem.condition:
                            if lit.atom.ast_type == ASTType.SymbolicAtom:
                                if lit.atom.symbol.ast_type == ASTType.Pool:
                                    key = (lit.atom.symbol.arguments[0].name, len(lit.atom.symbol.arguments[0].arguments))
                                else:
                                    key = (lit.atom.symbol.name, len(lit.atom.symbol.arguments))
                                if key not in self.atoms.keys():
                                    self.atoms[key] = [[self.numDef],[lit.location],[]]
                                    self.numDef += 1
                elif node.head.ast_type == ASTType.Literal:
                    if node.head.atom.ast_type == ASTType.SymbolicAtom:
                        if node.head.atom.symbol.ast_type == ASTType.Pool:
                            key = (node.head.atom.symbol.arguments[0].name, len(node.head.atom.symbol.arguments[0].arguments))
                        else:
                            key = (node.head.atom.symbol.name, len(node.head.atom.symbol.arguments))
                        if key not in self.atoms.keys():
                            if node.head.sign == 0:
                                self.atoms[key] = [[self.numDef],[node.head.location],[len(self.rules)-1]]
                                self.numDef += 1
                            else:
                                self.atoms[key] = [[self.numDef], [node.head.location],[]]
                                self.numDef += 1
                        else:
                            if node.head.sign == 0:
                                if not self.atoms[key][2]:
                                    self.atoms[key][1] = []
                                self.atoms[key][1].append(node.head.location)
                                self.atoms[key][2].append(len(self.rules)-1)
                elif node.head.ast_type == ASTType.HeadAggregate:
                    for elem in node.head.elements:
                        if elem.condition.literal.atom.ast_type == ASTType.SymbolicAtom:
                            if elem.condition.literal.atom.symbol.ast_type == ASTType.Pool:
                                key = (elem.condition.literal.atom.symbol.arguments[0].name, len(elem.condition.literal.atom.symbol.arguments[0].arguments))
                            else:
                                key = (elem.condition.literal.atom.symbol.name, len(elem.condition.literal.atom.symbol.arguments))
                            if key not in self.atoms.keys():
                                if elem.condition.literal.sign == 0:
                                    self.atoms[key] = [[self.numDef],[elem.condition.literal.location],[len(self.rules)-1]]
                                    self.numDef += 1
                                else:
                                    self.atoms[key] = [[self.numDef],[elem.condition.literal.location],[]]
                                    self.numDef += 1
                            else:
                                if elem.condition.literal.sign == 0:
                                    if not self.atoms[key][2]:
                                        self.atoms[key][1] = []
                                    self.atoms[key][1].append(elem.condition.literal.location)
                                    self.atoms[key][2].append(len(self.rules)-1)
                        for lit in elem.condition.condition:
                            if lit.atom.ast_type == ASTType.SymbolicAtom:
                                if lit.atom.symbol.ast_type == ASTType.Pool:
                                    key = (lit.atom.symbol.arguments[0].name, len(lit.atom.symbol.arguments[0].arguments))
                                else:
                                    key = (lit.atom.symbol.name, len(lit.atom.symbol.arguments))
                                if key not in self.atoms.keys():
                                    self.atoms[key] = [[self.numDef],[lit.location],[]]
                                    self.numDef += 1
                ### Body ###
                for atm in node.body:
                    if atm.ast_type == ASTType.Literal:
                        if atm.atom.ast_type == ASTType.SymbolicAtom:
                            if atm.atom.symbol.ast_type == ASTType.Pool:
                                key = (atm.atom.symbol.arguments[0].name, len(atm.atom.symbol.arguments[0].arguments))
                            else:
                                key = (atm.atom.symbol.name, len(atm.atom.symbol.arguments))
                            if key not in self.atoms.keys():
                                self.atoms[key] = [[self.numDef],[atm.location],[]]
                                self.numDef += 1
                        elif atm.atom.ast_type == ASTType.Aggregate:
                            for elem in atm.atom.elements:
                                if elem.literal.atom.ast_type == ASTType.SymbolicAtom:
                                    if elem.literal.atom.symbol.ast_type == ASTType.Pool:
                                        key = (elem.literal.atom.symbol.arguments[0].name, len(elem.literal.atom.symbol.arguments[0].arguments))
                                    else:
                                        key = (elem.literal.atom.symbol.name, len(elem.literal.atom.symbol.arguments))
                                    if key not in self.atoms.keys():
                                        self.atoms[key] = [[self.numDef],[elem.literal.location],[]]
                                        self.numDef += 1
                                for lit in elem.condition:
                                    if lit.atom.ast_type == ASTType.SymbolicAtom:
                                        if lit.atom.symbol.ast_type == ASTType.Pool:
                                            key = (lit.atom.symbol.arguments[0].name, len(lit.atom.symbol.arguments[0].arguments))
                                        else:
                                            key = (lit.atom.symbol.name, len(lit.atom.symbol.arguments))
                                        if key not in self.atoms.keys():
                                            self.atoms[key] = [[self.numDef],[lit.location],[]]
                                            self.numDef += 1
                        elif atm.atom.ast_type == ASTType.BodyAggregate:
                            for elem in atm.atom.elements:
                                for lit in elem.condition:
                                    if lit.atom.ast_type == ASTType.SymbolicAtom:
                                        if lit.atom.symbol.ast_type == ASTType.Pool:
                                            key = (lit.atom.symbol.arguments[0].name, len(lit.atom.symbol.arguments[0].arguments))
                                        else:
                                            key = (lit.atom.symbol.name, len(lit.atom.symbol.arguments))
                                        if key not in self.atoms.keys():
                                            self.atoms[key] = [[self.numDef],[lit.location],[]]
                                            self.numDef += 1                             
                    elif atm.ast_type == ASTType.ConditionalLiteral:
                            if atm.literal.atom.ast_type == ASTType.SymbolicAtom:
                                if atm.literal.atom.symbol.ast_type == ASTType.Pool:
                                    key = (atm.literal.atom.symbol.arguments[0].name, len(atm.literal.atom.symbol.arguments[0].arguments))
                                else:
                                    key = (atm.literal.atom.symbol.name, len(atm.literal.atom.symbol.arguments))
                                if key not in self.atoms.keys():
                                    self.atoms[key] = [[self.numDef],[atm.literal.location],[]]
                                    self.numDef += 1
                            for lit in atm.condition:
                                if lit.atom.ast_type == ASTType.SymbolicAtom:
                                    if lit.atom.symbol.ast_type == ASTType.Pool:
                                        key = (lit.atom.symbol.arguments[0].name, len(lit.atom.symbol.arguments[0].arguments))
                                    else:
                                        key = (lit.atom.symbol.name, len(lit.atom.symbol.arguments))
                                    if key not in self.atoms.keys():
                                        self.atoms[key] = [[self.numDef],[lit.location],[]]
                                        self.numDef += 1
                                        
                # if str(node.head) == "#false":
                #     self.rules.remove(node)
                #     self.constraintcounter += 1
                    # pos = ast.Position('<string>', 1, 1)
                    # loc = ast.Location(pos, pos)
                    # lit = ast.Literal(loc, ast.Sign.NoSign, ast.BooleanConstant(1))
                    # return node.update(head=lit)
        elif node.ast_type == ASTType.ShowTerm or node.ast_type == ASTType.ShowSignature:    
            if not prog:
                pos = ast.Position('<string>', 1, 1)
                loc = ast.Location(pos, pos)
                lit = ast.Literal(loc, ast.Sign.NoSign, ast.BooleanConstant(1))
                return ast.Rule(loc, lit, [])
        return node


    def setup(self):
        self.add_program()
        if self.args.rule or self.args.definition or self.args.loop or self.args.component:
            self.add_rules()
            
        if self.args.definition or self.args.loop or self.args.component:
            self.add_definitions()
            
        if self.args.loop or self.args.component:
            self.graph = build_dependency_graph(self.rules, self.atoms)
            self.sccs = find_sccs(self.graph)

        if self.args.loop:
            self.loops = find_loops(self.graph, self.sccs)
            self.add_loops()

        if self.args.component:
            self.add_sccs()


    def check_rule_positive(self):
        self.posRCov.update(set([label for label in self.model if label.startswith("_r")]))

    def check_rule_negative(self):
        self.negRCov.update(set([label for label in self.model if label.startswith("-_r")]))

    def check_definition_positive(self):
        self.posDCov.update(set([label for label in self.model if label.startswith("_d")]))

    def check_definition_negative(self):
        self.negDCov.update(set([label for label in self.model if label.startswith("-_d")]))

    def check_component_positive(self):
        self.posCCov.update(set([label for label in self.model if label.startswith("_c")]))

    def check_component_negative(self):
        self.negCCov.update(set([label for label in self.model if label.startswith("-_c")]))

    def check_loop_positive(self):
        self.posLCov.update(set([label for label in self.model if label.startswith("_l")]))

    def check_loop_negative(self):
        self.negLCov.update(set([label for label in self.model if label.startswith("-_l")]))


    def check_coverage(self):
        if self.args.rule or self.args.definition or self.args.loop or self.args.component:
            self.ctl.configuration.solve.enum_mode = "brave"
            self.ctl.configuration.solve.opt_mode = "ignore"
            self.ctl.ground([("base", [])])
            res = self.ctl.solve(on_model=self.on_model)
            if res.satisfiable:
                if self.args.rule:
                    self.check_rule_positive()
                    self.check_rule_negative()
                if self.args.definition:
                    self.check_definition_positive()
                    self.check_definition_negative()
                if self.args.loop:
                    self.check_loop_positive()
                    self.check_loop_negative()
                if self.args.component:
                    self.check_component_positive()
                    self.check_component_negative()
            else:
                print("Please enter a correct Program/Testcase (solve call unsatisfiable)")
                return 0
        if self.args.program:
            if self.program_coverage() == 0:
                return 0

        # for loop in self.loops:
        #     print([atm.atom.symbol.name for atm in loop])
        # for scc in self.sccs:
        #     print([atm.atom.symbol.name for atm in scc])
        # print(self.posCCov)
        # print(self.negRCov)
        # print(self.heads) 
        # print(self.rules)    
        # print(self.loops)
        # print(self.sccs)
           
    def print_coverage(self):

        if self.args.rule:
            positiveR = (len(self.posRCov)*100) / self.numRules if self.numRules else 100
            negativeR = (len(self.negRCov)*100) / self.numRules if self.numRules else 100
            print(f"\nPositive rule coverage: {positiveR:.3g}% ({len(self.posRCov)} out of {self.numRules} rules)")
            print(f"Negative rule coverage: {negativeR:.3g}% ({len(self.negRCov)} out of {self.numRules} rules)")
            if self.args.verbose:
                if positiveR != 100:
                    self.print_pos_Rcoverage()
                if negativeR != 100:
                    self.print_neg_Rcoverage()

        if self.args.definition:
            positiveD = (len(self.posDCov)*100) / self.numDef if self.numDef else 100
            negativeD = (len(self.negDCov)*100) / self.numDef if self.numDef else 100
            print(f"\nPositive definition coverage: {positiveD:.3g}% ({len(self.posDCov)} out of {self.numDef} atoms)")
            print(f"Negative definition coverage: {negativeD:.3g}% ({len(self.negDCov)} out of {self.numDef} atoms)")
            if self.args.verbose:
                if positiveD != 100:
                    self.print_pos_Dcoverage()
                if negativeD != 100:
                    self.print_neg_Dcoverage()

        if self.args.loop:
            positiveL = ((len(self.posLCov) + len(self.posDCov)) * 100) / (self.numDef + len(self.loops)) if (self.numDef + len(self.loops)) else 100
            negativeL = ((len(self.negLCov) + len(self.negDCov)) * 100) / (self.numDef + len(self.loops)) if (self.numDef + len(self.loops)) else 100
            print(f"\nPositive loop coverage: {positiveL:.3g}% ({len(self.posLCov) + len(self.posDCov)} out of {self.numDef + len(self.loops)} loops)")
            print(f"Negative loop coverage: {negativeL:.3g}% ({len(self.negLCov) + len(self.negDCov)} out of {self.numDef + len(self.loops)} loops)")
            if self.args.verbose:
                if positiveL != 100:
                    self.print_pos_Lcoverage()
                if negativeL != 100:
                    self.print_neg_Lcoverage()

        if self.args.component:
            positiveC = (len(self.posCCov) * 100) / (len(self.sccs)) if len(self.sccs) else 100
            negativeC = (len(self.negCCov) * 100) / (len(self.sccs)) if len(self.sccs) else 100
            print(f"\nPositive component coverage: {positiveC:.3g}% ({len(self.posCCov)} out of {len(self.sccs)} components)")
            print(f"Negative component coverage: {negativeC:.3g}% ({len(self.negCCov)} out of {len(self.sccs)} components)")
            if self.args.verbose:
                if positiveC != 100:
                    self.print_pos_Ccoverage()
                if negativeC != 100:
                    self.print_neg_Ccoverage()

        if self.args.program:
            max = 2 ** self.numRules
            positiveP = (len(self.pCov)*100) / max if max else 100
            print(f"\nProgram coverage: {positiveP:.3g}% ({len(self.pCov)} out of {max} subprograms)")                   


    def print_pos_Rcoverage(self):
        cov = [int(label[2:]) for label in self.posRCov]
        notcov = [idx for idx in range(self.numRules) if idx not in cov]

        print("\nRules that have not been positively rule-covered:")
        for idx in notcov:
            print(str(self.rules[idx]) + "\nline: {}, column: {}".format(self.rules[idx].location[0][1], self.rules[idx].location[0][2]))

    def print_neg_Rcoverage(self):
        cov = set([int(label[3:]) for label in self.negRCov])
        notcov = [idx for idx in range(self.numRules) if idx not in cov]

        print("\nRules that have not been negatively rule-covered:")
        for idx in notcov:
            print(str(self.rules[idx]) + "\nline: {}, column: {}".format(self.rules[idx].location[0][1], self.rules[idx].location[0][2]))

    def print_pos_Dcoverage(self):
        cov = [int(label[2:]) for label in self.posDCov]

        print("\nAtoms that have not been positively definition-covered:")
        for idx, (atm, values) in enumerate(self.atoms.items()):
            if idx not in cov:
                print(atm)
                for loc in values[1]:
                    print("line: {}, column: {}".format(loc.begin[1], loc.begin[2]))

    def print_neg_Dcoverage(self):
        cov = [int(label[3:]) for label in self.negDCov]

        print("\nAtoms that have not been negatively definition-covered:")
        for idx, (atm, values) in enumerate(self.atoms.items()):
            if idx not in cov:
                print(atm)
                for loc in values[1]:
                    print("line: {}, column: {}".format(loc.begin[1], loc.begin[2]))

    def print_pos_Lcoverage(self):
        cov = [int(label[2:]) for label in self.posLCov]

        print("\nLoops that have not been positively loop-covered:", end='')
        for idx, loop in enumerate(self.loops):
            if idx not in cov:
                print("\n", [atm[0] for atm in loop], sep='')
                for atm in loop:
                    print(atm)
                    locs = self.atoms[atm][1]
                    for j in range(len(locs)):
                        print("line: {}, column: {}".format(locs[j].begin[1], locs[j].begin[2]))


    def print_neg_Lcoverage(self):
        cov = [int(label[3:]) for label in self.negLCov]

        print("\nLoops that have not been negatively loop-covered:", end='')
        for idx, loop in enumerate(self.loops):
            if idx not in cov:
                print("\n", [atm[0] for atm in loop], sep='')
                for atm in loop:
                    print(atm)
                    locs = self.atoms[atm][1]
                    for j in range(len(locs)):
                        print("line: {}, column: {}".format(locs[j].begin[1], locs[j].begin[2]))


    def print_pos_Ccoverage(self):
        cov = [int(label[2:]) for label in self.posCCov]

        print("\nComponents that have not been positively component-covered:", end='')
        for idx, scc in enumerate(self.sccs):
            if idx not in cov:
                print("\n", [atm[0] for atm in scc], sep='')
                for atm in scc:
                    print(atm)
                    locs = self.atoms[atm][1]
                    for j in range(len(locs)):
                        print("line: {}, column: {}".format(locs[j].begin[1], locs[j].begin[2]))

    def print_neg_Ccoverage(self):
        cov = [int(label[3:]) for label in self.negCCov]

        print("\nComponents that have not been negatively component-covered:", end='')
        for idx, scc in enumerate(self.sccs):
            if idx not in cov:
                print("\n", [atm[0] for atm in scc], sep='')
                for atm in scc:
                    print(atm)
                    locs = self.atoms[atm][1]
                    for j in range(len(locs)):
                        print("line: {}, column: {}".format(locs[j].begin[1], locs[j].begin[2]))


    def on_model_prog(self, model):
        self.pCov.add(tuple([atm.name for atm in model.symbols(atoms=True) if atm.name.startswith("_r")]))
        # print(self.pCov)


    def program_coverage(self):
        self.ctl = Control(["0"], message_limit=0)
        self.ctl.configuration.solve.opt_mode = "ignore"
        self.numTestcases = 0
        for file in self.args.testcases:
            parse_files([file], self.add_input)
            self.numTestcases += 1
        with ProgramBuilder(self.ctl) as bld:
            if not self.rules:
                parse_files(self.args.files, lambda stm: bld.add(self.gather_info(stm, prog=True)))
                self.numRules = len(self.rules) + self.constraintcounter
            else:
                parse_files(self.args.files, bld.add)
            str = "{ " + " ".join([f"_i{num};" for num in range(self.numTestcases)])[:-1] + " } = 1."
            parse_string(str, bld.add)
        self.add_rules()
        self.ctl.ground([("base", [])])
        res = self.ctl.solve(on_model=self.on_model_prog)
        if not res.satisfiable:
            print("Solve call unsatisfiable during program coverage!")
            return 0

    def full_check(self):
        self.setup()
        if self.check_coverage() != 0:
            self.print_coverage()
