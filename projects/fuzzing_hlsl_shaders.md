



Here is some stuff:

```
Ok, so now it actually fuzzes the stuff correctly!!!
now, I have whipped up a similar custom mutator I want to build for hlsl already in glsl for the ANGLE shader translator. Here is the source code for it:
`# shader_mutator.py
from __future__ import annotations

from dataclasses import replace
from typing import Dict, List, Optional, Tuple, Union
import copy
# from copy import deepcopy
import random

from shader_ast import *
# Import the constants from const.py ...
from const import *

from utils import * # For deepclone

# For the builtin functions etc...
from builtin_data import BUILTIN_FUNCTIONS

# Debugging???

# DEBUG = True

DEBUG = False

# if DEBUG:# Originally was conditional
import shader_unparser

stop = False

def dlog(msg: str): # Debug logging...
    if DEBUG:
        print("[DEBUG] "+str(msg))
    return

def dexit(msg: str = None): # Exit with error code 1 if in debugging mode...
    if DEBUG:
        if msg != None:
            dlog("[EXITING]: "+str(msg))
        exit(1)
    return

# ----------------------------
# Utilities
# ----------------------------

# Can not be put into const.py since needs the IntLiteral etc stuff.
NUMERIC_LITERALS = {
    "int":   lambda r: IntLiteral(r.randrange(0, 10)), # "int":   lambda r: IntLiteral(r.randrange(-10, 10)),
    "uint":  lambda r: IntLiteral(r.randrange(0, 10)),
    "float": lambda r: FloatLiteral(r.choice([0.0, 0.5, 1.0, -1.0, 2.0])),
    "bool":  lambda r: BoolLiteral(r.choice([True, False])),
}





def coin(rng: random.Random, p: float) -> bool:
    return rng.random() < p

def choose(rng: random.Random, xs: List):
    return xs[rng.randrange(len(xs))] if xs else None

def has_side_effect(e: Expr) -> bool:
    if isinstance(e, (CallExpr,)):
        return True
    if isinstance(e, UnaryExpr) and e.op in ("++", "--"):
        return True
    if isinstance(e, BinaryExpr) and e.op in ("=", "+=", "-=", "*=", "/="):
        return True
    return False


# These next utilities are for creating composite types more smartly...

def is_vector_name(name: str) -> bool:
    return name in VEC_TYPE_FLATTENED

def is_matrix_name(name: str) -> bool:
    return name in {"mat2","mat3","mat4"}

def is_struct_like(env, name: str) -> bool:
    return (name in env.struct_defs) or (name in env.interface_blocks)

def is_composite(ti: TypeInfo, env) -> bool:
    if ti is None:
        return False
    if ti.is_array():
        return True
    n = ti.name
    return is_vector_name(n) or is_matrix_name(n) or is_struct_like(env, n)

def gen_struct_vardecl(scope: Scope, env: Env, rng: random.Random) -> Optional[DeclStmt]:
    if not env.struct_defs:
        return None

    sname = rng.choice(list(env.struct_defs.keys()))
    vname = f"s_{rng.randrange(10000)}"

    ti = TypeInfo(sname)
    scope.define(vname, ti)

    init = None
    if coin(rng, 0.7):
        init = gen_constructor_expr(ti, scope, env, rng)

    vd = VarDecl(TypeName(sname), vname, init=init, array_dims=None)
    return DeclStmt([vd])

def abort(msg: str): # Crash with message
    assert False, msg

def is_lvalue_expr(e: Expr) -> bool: # left hand side value???
    return isinstance(e, (Identifier, IndexExpr, MemberExpr))

def infer_expr_type(e: Expr, scope: Scope, env: Env) -> Optional[TypeInfo]: # Try to infer type from expression...
    if isinstance(e, IntLiteral):
        return TypeInfo("int")

    if isinstance(e, FloatLiteral):
        return TypeInfo("float")

    if isinstance(e, BoolLiteral):
        return TypeInfo("bool")

    if isinstance(e, Identifier):
        return scope.lookup(e.name) or env.globals.get(e.name)

    if isinstance(e, UnaryExpr):
        return infer_expr_type(e.operand, scope, env)

    if isinstance(e, BinaryExpr):
        if e.op in ("&&", "||", "<", ">", "<=", ">=", "==", "!="):
            return TypeInfo("bool")
        return infer_expr_type(e.left, scope, env)

    if isinstance(e, TernaryExpr):
        return infer_expr_type(e.then_expr, scope, env)

    if isinstance(e, CallExpr):
        if isinstance(e.callee, Identifier):
            fn = env.funcs.get(e.callee.name)
            if fn:
                ret, _ = fn
                return ret
        return None

    if isinstance(e, MemberExpr):
        base_t = infer_expr_type(e.base, scope, env)
        if base_t and base_t.name in env.struct_defs:
            for f in env.struct_defs[base_t.name]:
                if f.name == e.member:
                    return structfield_to_typeinfo(f)
        return None

    if isinstance(e, IndexExpr):
        base_t = infer_expr_type(e.base, scope, env)
        if base_t:
            return base_t.elem()
        return None

    return None

def mutate_expr_typed(e, want, rng, scope, env):
    if coin(rng, 0.05):
        return gen_expr(want, scope, env, rng)
    return mutate_expr(e, rng, scope, env)

# This is used to select the qualifiers

def mutate_declarator_qualifiers(
    d: Declarator,
    rng: random.Random,
    *,
    storage_pool=STORAGE_QUALIFIERS,
    precision_pool=PRECISION_QUALIFIERS,
    interp_pool=None,
    p_add=0.4,
    p_remove=0.3,
    p_replace=0.2,
) -> None:
    """
    Mutate qualifiers in-place on a Declarator.
    """

    qs = set(d.qualifiers or [])

    all_allowed = set(storage_pool)
    if interp_pool:
        all_allowed |= set(interp_pool)
    all_allowed |= set(precision_pool)

    # remove
    if qs and coin(rng, p_remove):
        qs.remove(rng.choice(list(qs)))

    # add
    if coin(rng, p_add):
        q = rng.choice(list(all_allowed))
        if q is not None:
            qs.add(q)

    # replace
    if qs and coin(rng, p_replace):
        qs.clear()
        q = rng.choice(list(all_allowed))
        if q is not None:
            qs.add(q)

    d.qualifiers = list(qs)


def pick_builtin_image(scope: Scope, env: Env, rng: random.Random) -> Identifier | None:
    candidates = []

    # Collect all visible variables
    all_vars = scope.all_vars()
    for name, ti in env.globals.items():
        if name not in all_vars:
            all_vars[name] = ti

    for name, ti in all_vars.items():
        if ti.name in IMAGE_TYPE_TO_COORD:
            candidates.append(name)

    # dlog("Here is the candidates list for type")

    if not candidates:
        return None  # caller should gracefully bail

    return Identifier(rng.choice(candidates))

def gen_coord_for_image(image_expr: Identifier, scope: Scope, env: Env, rng: random.Random) -> Expr:
    ti = scope.lookup(image_expr.name) or env.globals.get(image_expr.name)
    if ti is None:
        # Extremely defensive fallback
        return IntLiteral(0)

    coord_type = IMAGE_TYPE_TO_COORD.get(ti.name)
    if coord_type is None:
        # Should never happen if pick_builtin_image is correct
        return IntLiteral(0)

    return gen_expr(TypeInfo(coord_type), scope, env, rng)

def find_struct_def_index(items, struct_name: str) -> int | None:
    for i, item in enumerate(items):
        if isinstance(item, StructDef) and item.name == struct_name:
            return i
    return None

# ----------------------------
# Type info helpers
# ----------------------------

class TypeInfo:
    """
    Minimal typing support.
    name: like "float" or "foo" (user struct)
    array_dims: list of dims (None means unsized)
    """
    def __init__(self, name: str, array_dims: Optional[List[Optional[Expr]]] = None):
        self.name = name
        self.array_dims = list(array_dims or [])

    def is_array(self) -> bool:
        return len(self.array_dims) > 0

    def elem(self) -> "TypeInfo":
        if not self.array_dims:
            return self
        return TypeInfo(self.name, self.array_dims[1:])

    def __repr__(self):
        return f"TypeInfo({self.name}, dims={len(self.array_dims)})"


def typename_to_typeinfo(t: Union[TypeName, StructType]) -> TypeInfo:
    if isinstance(t, TypeName):
        return TypeInfo(t.name, [])
    if isinstance(t, StructType):
        # struct specifier type: name may be None
        return TypeInfo(t.name or "<anon_struct>", [])
    # fallback
    return TypeInfo(str(t), [])


def vardecl_to_typeinfo(v: VarDecl) -> TypeInfo:
    base = typename_to_typeinfo(v.type_name)
    return TypeInfo(base.name, getattr(v, "array_dims", []) or [])


def structfield_to_typeinfo(f: StructField) -> TypeInfo:
    base = typename_to_typeinfo(f.type_name)
    # StructField currently has array_size (single) OR you may later add array_dims.
    dims = []
    if hasattr(f, "array_dims") and f.array_dims is not None:
        dims = list(f.array_dims)
    elif getattr(f, "array_size", None) is not None:
        dims = [f.array_size]
    return TypeInfo(base.name, dims)


# ----------------------------
# Symbol table + environment
# ----------------------------

class Env:
    def __init__(self):
        # struct name -> list of StructField (definition shape)
        self.struct_defs: Dict[str, List[StructField]] = {}

        # var name -> TypeInfo
        self.globals: Dict[str, TypeInfo] = {}

        # function name -> signature (optional; not needed much)
        self.funcs: Dict[str, Tuple[TypeInfo, List[TypeInfo]]] = {}

        # interface block "names" are essentially types too
        # (we treat them like structs for member mutation)
        self.interface_blocks: Dict[str, List[StructField]] = {}

    def clone(self) -> "Env":
        e = Env()
        e.struct_defs = deepclone(self.struct_defs)
        e.globals = deepclone(self.globals)
        e.funcs = deepclone(self.funcs)
        e.interface_blocks = deepclone(self.interface_blocks)
        return e


class Scope:
    def __init__(self, parent: Optional["Scope"] = None):
        self.parent = parent
        self.vars: Dict[str, TypeInfo] = {}

    def define(self, name: str, ti: TypeInfo):
        self.vars[name] = ti

    def lookup(self, name: str) -> Optional[TypeInfo]:
        s: Optional[Scope] = self
        while s is not None:
            if name in s.vars:
                return s.vars[name]
            s = s.parent
        return None

    def all_vars(self) -> Dict[str, TypeInfo]:
        out = {}
        s: Optional[Scope] = self
        while s is not None:
            out.update(s.vars)
            s = s.parent
        return out


# ----------------------------
# Collect definitions
# ----------------------------

def _flatten_members(members):
    out = []
    for m in members:
        if isinstance(m, list):
            out.extend(m)
        else:
            out.append(m)
    return out

def build_env(tu: TranslationUnit) -> Env:
    env = Env()
    for item in tu.items:
        if isinstance(item, StructDef):
            env.struct_defs[item.name] = list(item.fields)

        elif isinstance(item, StructDecl):
            # If it is a named struct specifier, capture fields as a "def"
            st = item.struct_type
            if st.name:
                env.struct_defs[st.name] = list(st.members)

        elif isinstance(item, InterfaceBlock):
            # Treat interface block type name as a struct-like thing with members
            members = _flatten_members(item.members)
            env.interface_blocks[item.name] = list(members)
            # Also: its "instance" becomes a global var with that "type"
            if item.instance:
                env.globals[item.instance] = TypeInfo(item.name, [])

        elif isinstance(item, GlobalDecl):
            for d in item.decls:
                env.globals[d.name] = vardecl_to_typeinfo(d)

        elif isinstance(item, FunctionDef):
            # record function name, return + param types
            ret = typename_to_typeinfo(item.return_type)
            params = [typename_to_typeinfo(p.type_name) for p in item.params]
            env.funcs[item.name] = (ret, params)

    return env


# ----------------------------
# Candidate pools
# ----------------------------

def candidates_by_type(scope: Scope, env: Env, want: Optional[TypeInfo]) -> List[str]:
    """
    Prefer same base type name (ignore array dims for now),
    otherwise allow anything.
    """
    allv = scope.all_vars()
    # add globals into scope view (if not already)
    for k, v in env.globals.items():
        if k not in allv:
            allv[k] = v

    names = list(allv.keys())
    if not want:
        return names

    same = [n for n, ti in allv.items() if ti.name == want.name]
    if same:
        return same
    # return names
    # Here actually return an empty list, because otherwise we get bogus types...
    return []


def all_struct_field_names(env: Env, struct_name: str) -> List[str]:
    if struct_name in env.struct_defs:
        return [f.name for f in env.struct_defs[struct_name]]
    if struct_name in env.interface_blocks:
        return [f.name for f in env.interface_blocks[struct_name]]
    return []

def array_len_from_typeinfo(ti: TypeInfo) -> int | None:
    dims = getattr(ti, "array_dims", None)
    if not dims:
        return None  # not an array

    # True multidimensional array (e.g. int a[2][3])
    if len(dims) > 1:
        abort("Multidimensional arrays not supported...")

    d0 = dims[0]

    # Case: unsized array -> float a[];
    if d0 == []:
        return None

    # Flatten accidental nesting: [[100]] → [100]
    if isinstance(d0, list):
        if len(d0) != 1:
            abort("Unexpected array dimension structure")
        d0 = d0[0]

    # Constant integer
    if isinstance(d0, int):
        return d0

    # AST literal like IntLiteral(100)
    if hasattr(d0, "value") and isinstance(d0.value, int):
        return d0.value

    # String token "100"
    if isinstance(d0, str) and d0.isdigit():
        return int(d0)

    # Non-constant expression → cannot expand
    return None

def get_indexable_length(ti: TypeInfo) -> Optional[int]:
    if ti is None:
        return None
    if ti.is_array():
        return array_len_from_typeinfo(ti)
    if ti.name in ("vec2", "ivec2", "uvec2", "bvec2"):
        return 2
    if ti.name in ("vec3", "ivec3", "uvec3", "bvec3"):
        return 3
    if ti.name in ("vec4", "ivec4", "uvec4", "bvec4"):
        return 4
    return None

# ----------------------------
# Mutations: generate expressions
# ----------------------------

MAX_EXPLICIT_ARRAY = 150 # Don't try to generate explicit arrays larger than this, because otherwise it takes two years to generate one...

def gen_atom(want: TypeInfo, scope, env, rng) -> Expr:

    if not want: # Just an extra check. TODO: Get rid of this bullshit here...
        return NUMERIC_LITERALS["int"](rng)

    name = want.name

    n = array_len_from_typeinfo(want)

    # Array case
    if n is not None:
        base = TypeInfo(name)  # IMPORTANT: strip array dims
        if n > MAX_EXPLICIT_ARRAY:
            zero = gen_atom(base, scope, env, rng)
            return CallExpr(Identifier(f"{name}[{n}]"), [zero])
        else:
            elems = [gen_atom(base, scope, env, rng) for _ in range(n)]
            return CallExpr(Identifier(f"{name}[{n}]"), elems)

    # Unsized array → generate a reasonable default
    if want.array_dims == [[]]:
        base = TypeInfo(name)
        zero = gen_atom(base, scope, env, rng)
        return CallExpr(Identifier(f"{name}[1]"), [zero])

    # if n is not None and want.array_dims == [[]]:
    #     return gen_atom(TypeInfo(name), scope, env, rng)

    # Scalars
    if name in NUMERIC_LITERALS:
        return NUMERIC_LITERALS[name](rng)
    if name == "bool":
        return BoolLiteral(bool(rng.getrandbits(1)))

    # Vectors / matrices
    if "vec" in name: # name.startswith("vec"):
        return gen_vector(name, scope, env, rng, atom=True)
    if "mat" in name: # name.startswith("mat"):
        return gen_matrix(name, scope, env, rng, atom=True)

    # Structs
    if name in env.struct_defs:
        fields = env.struct_defs[name]
        args = [gen_atom(structfield_to_typeinfo(f), scope, env, rng) for f in fields]
        return CallExpr(Identifier(name), args)

    abort(f"gen_atom: cannot build {want}")

# What kind of expression?

class ExprKind:
    RVALUE = "rvalue"
    LVALUE = "lvalue"

def gen_expr(
    want: Optional[TypeInfo],
    scope: Scope,
    env: Env,
    rng: random.Random,
    depth: int = 0,
    kind=ExprKind.RVALUE,
) -> Expr:

    if depth >= MAX_EXPR_DEPTH:
        # abort("Max depth exceeded...")
        l = gen_leaf(want, scope, env, rng, kind)
        return l

    choices = []

    # composite type (matrixes etc...)

    if want is None and coin(rng, 0.9): # 90% chance of trying to generatae some inferred type...
        want = rng.choice([
            TypeInfo("float"),
            TypeInfo("vec4"),
            TypeInfo("ivec2"),
            TypeInfo(rng.choice(list(env.struct_defs.keys()))) if env.struct_defs else TypeInfo("float")
        ])

    if want and is_composite(want, env) and coin(rng, 0.90): # 30 percent change to to something like this...
        # print("Hit the thing...")
        ctor = gen_constructor_expr(want, scope, env, rng)
        if ctor:
            return ctor

    # leaf
    choices.append(lambda: gen_leaf(want, scope, env, rng, kind))

    # unary
    if want and want.name in ("int", "float", "bool"):
        choices.append(lambda: gen_unary(want, scope, env, rng, depth))

    # binary
    if want and want.name in ("int", "float", "bool"):
        choices.append(lambda: gen_binary(want, scope, env, rng, depth))

    # ternary (boolean condition)
    if want:
        choices.append(lambda: gen_ternary(want, scope, env, rng, depth))

    # function call
    choices.append(lambda: gen_call(want, scope, env, rng, depth))

    # struct member access
    choices.append(lambda: gen_member_access(want, scope, env, rng, depth))

    return rng.choice(choices)()

def gen_leaf(want, scope, env, rng, kind):

    if not want: # want is null, so any type goes...
        return gen_atom(want, scope, env, rng)

    name = want.name # Get name

    vars = candidates_by_type(scope, env, want)

    if vars and coin(rng, 0.20): # Instead of automatically using a variable, throw a coin instead...
        name = rng.choice(vars)
        return Identifier(name)

    if kind == ExprKind.LVALUE:
        # cannot generate literal as lvalue
        return Identifier(rng.choice(list(scope.all_vars().keys())))

    if want and name in NUMERIC_LITERALS:
        return NUMERIC_LITERALS[name](rng)

    # Check for banned types...
    if want and name in OPAQUE_TYPES:
        # Only valid leaf is an identifier of that type
        vars = candidates_by_type(scope, env, want)
        if vars:
            return Identifier(rng.choice(vars))
        # otherwise: give up gracefully
        return NUMERIC_LITERALS["int"](rng)

    # Instead of aborting, just call the atom thing...
    return gen_atom(want, scope, env, rng)
    # abort("Reached end of gen_leaf with want == "+str(want))
    # return IntLiteral(0)

def gen_assignment_stmt(scope, env, rng):
    lhs = gen_expr(None, scope, env, rng, kind=ExprKind.LVALUE)
    rhs = gen_expr(None, scope, env, rng)
    op = rng.choice(["=", "+=", "-=", "*=", "/="])
    return ExprStmt(BinaryExpr(op, lhs, rhs))

BIN_OPS = {
    "int":   ["+", "-", "*", "/", "%"],
    "float": ["+", "-", "*", "/"],
    "bool":  ["&&", "||"],
}

def gen_binary(want, scope, env, rng, depth):
    op = rng.choice(BIN_OPS.get(want.name, ["+"]))

    left = gen_expr(want, scope, env, rng, depth + 1)
    right = gen_expr(want, scope, env, rng, depth + 1)

    return BinaryExpr(op, left, right)

UNARY_OPS = {
    "int": ["+", "-"], # This originally had "~" too...
    "float": ["+", "-"],
    "bool": ["!"],
}

def gen_unary(want, scope, env, rng, depth):
    op = rng.choice(UNARY_OPS.get(want.name, ["+"]))

    operand = gen_expr(want, scope, env, rng, depth + 1)
    return UnaryExpr(op, operand, postfix=False)

def gen_ternary(want, scope, env, rng, depth):
    cond = gen_expr(TypeInfo("bool"), scope, env, rng, depth + 1)
    t = gen_expr(want, scope, env, rng, depth + 1)
    f = gen_expr(want, scope, env, rng, depth + 1)
    return TernaryExpr(cond, t, f)


def gen_builtin_call(want, scope, env, rng, depth):
    candidates = []

    for fname, info in BUILTIN_FUNCTIONS.items():
        ret = info["return"]
        if want is None or ret == want.name:
            candidates.append((fname, info))

    if not candidates:
        return None

    fname, info = rng.choice(candidates)
    args = []

    for p in info["params"]:
        base = p.split("[", 1)[0]
        # generic family
        if base in GENERIC_EXPANSION:
            concrete = rng.choice(GENERIC_EXPANSION[base])
            args.append(gen_expr(TypeInfo(concrete), scope, env, rng, depth + 1)) # Originally had "gen_expr(Type(concrete), ...)"
            continue

        # the IMAGE_PARAMS is a very special type. Handle it before handling other special types...

        if base == 'IMAGE_PARAMS':
            # exit(0)
            image_var = pick_builtin_image(scope, env, rng)
            if not image_var:
                return None # Unable to generate such a call...
            coord_expr = gen_coord_for_image(image_var)
            args.extend([image_var, coord_expr])
            continue

        # special opaque types → use builtin variables
        if base in SPECIAL_TYPES:
            var = env.get_builtin_var(base)
            if var is None:
                return None
            args.append(Identifier(var))
            continue

        # normal type
        args.append(gen_expr(TypeInfo(base), scope, env, rng, depth + 1)) # Originally had "gen_expr(Type(concrete), ...)"
    # dlog("Generated this thing here: "+str(fname)+"("+str(",".join([str(x) for x in args]))+")")
    # exit(0)
    return CallExpr(Identifier(fname), args)

def gen_call(want, scope, env, rng, depth):
    candidates = []

    if coin(rng, 0.10): # 10% chance to generate a builtin function call...
        call = gen_builtin_call(want, scope, env, rng, depth)
        if call: # Return the generated call if one was found...
            # assert False
            return call

    for fname, (ret, params) in env.funcs.items():
        if want is None or ret.name == want.name:
            candidates.append((fname, params))

    if not candidates:
        return gen_leaf(want, scope, env, rng, ExprKind.RVALUE)

    fname, params = rng.choice(candidates)
    args = [gen_expr(pt, scope, env, rng, depth + 1) for pt in params]

    return CallExpr(Identifier(fname), args)

# This code did not use nested structs correctly...
'''
def gen_member_access(want, scope, env, rng, depth):
    vars = [(n, ti) for n, ti in scope.all_vars().items()
            if ti.name in env.struct_defs]

    if not vars:
        return gen_leaf(want, scope, env, rng, ExprKind.RVALUE)

    name, ti = rng.choice(vars)
    fields = env.struct_defs[ti.name]

    f = rng.choice(fields)
    return MemberExpr(Identifier(name), f.name)
'''

def gen_member_access(want, scope, env, rng, depth):
    candidates = [(n, ti) for n, ti in scope.all_vars().items()
                  if ti.name in env.struct_defs]

    if not candidates:
        return gen_leaf(want, scope, env, rng, ExprKind.RVALUE)

    name, ti = rng.choice(candidates)
    expr = Identifier(name)

    for _ in range(rng.randint(1, 3)):
        fields = env.struct_defs.get(ti.name)
        if not fields:
            break
        f = rng.choice(fields)
        expr = MemberExpr(expr, f.name)
        ti = structfield_to_typeinfo(f)
        # Stop here for now...
        # global stop
        # stop = True

        if ti.name not in env.struct_defs:
            break

    return expr

def gen_if(scope, env, rng):
    cond = gen_expr(TypeInfo("bool"), scope, env, rng)
    thenb = BlockStmt([ExprStmt(gen_expr(None, scope, env, rng))])
    elseb = BlockStmt([ExprStmt(gen_expr(None, scope, env, rng))])
    return IfStmt(cond, thenb, elseb)

def gen_switch(scope, env, rng):
    expr = gen_expr(TypeInfo("int"), scope, env, rng)

    cases = []
    for i in range(rng.randint(1, 3)):
        body = [ExprStmt(gen_expr(None, scope, env, rng)), BreakStmt()]
        cases.append(CaseStmt(IntLiteral(i), body))

    if coin(rng, 0.5):
        cases.append(DefaultStmt([BreakStmt()]))

    return SwitchStmt(expr, BlockStmt(cases))

# ----------------------------
# Mutations: structure generation
# ----------------------------

def weighted_choice(rng, items):
    total = sum(w for _, w in items)
    r = rng.uniform(0, total)
    acc = 0
    for val, w in items:
        acc += w
        if acc >= r:
            return val

def gen_random_typename(rng, env, depth=0):
    """
    Returns a TypeName or StructType reference.
    depth limits recursive struct nesting.
    """

    choices = []

    # Scalars
    choices += [("scalar", 4)]

    # Vectors
    choices += [("vector", 4)]

    # Matrices
    choices += [("matrix", 2)]

    # Existing structs (allow nesting)
    if env.struct_defs and depth < 2:
        choices += [("struct", 3)]

    kind = weighted_choice(rng, choices)

    if kind == "scalar":
        return TypeName(rng.choice(SCALAR_TYPES))

    if kind == "vector":
        base = rng.choice(list(VECTOR_TYPES.keys()))
        return TypeName(rng.choice(VECTOR_TYPES[base]))

    if kind == "matrix":
        return TypeName(rng.choice(MATRIX_TYPES))

    if kind == "struct":
        name = rng.choice(list(env.struct_defs.keys()))
        return TypeName(name)

    # Fallback
    return TypeName("float")

def gen_random_struct_field(rng, env, depth): # Generate random structfield object
    t = gen_random_typename(rng, env, depth)

    name = f"f_{rng.randrange(10000)}"

    field = StructField(
        type_name=t,
        name=name,
        array_size=None
    )

    # Occasionally make it an array
    if rng.random() < 0.25:
        field.array_size = IntLiteral(rng.choice([1, 2, 3, 4, 8]))

    return field

def gen_struct_definition(new_items, rng, env):
    name = f"FuzzStruct{rng.randrange(100000)}"

    field_count = rng.randint(1, 6)

    fields = []
    for _ in range(field_count):
        fields.append(gen_random_struct_field(rng, env, depth=1))

    struct = StructDef(name, fields)

    new_items.insert(0, struct)
    env.struct_defs[name] = fields

def gen_matrix(name, scope, env, rng, atom=False):
    # Generate matrix
    n = int(name[-1])
    # args = [gen_expr(TypeInfo("float"), scope, env, rng) for _ in range(n * n)]
    integer = name[0] == "i" # Check for integer...
    # args = [gen_expr(TypeInfo("float"), scope, env, rng) for _ in range(n)]
    if integer:
        if atom:
            args = [IntLiteral(rng.choice([-1.0, -0.5, 0.0, 0.5, 1.0, 2.0])) for _ in range(n * n)]
        else:
            args = [gen_expr(TypeInfo("int"), scope, env, rng) for _ in range(n * n)]
    else:
        if atom:
            args = [FloatLiteral(rng.choice([-1.0, -0.5, 0.0, 0.5, 1.0, 2.0])) for _ in range(n * n)]
        else:
            args = [gen_expr(TypeInfo("float"), scope, env, rng) for _ in range(n * n)]

    return CallExpr(Identifier(name), args)

def gen_vector(name, scope, env, rng, atom=False):
    n = int(name[-1])
    integer = name[0] == "i" # Check for integer...
    # args = [gen_expr(TypeInfo("float"), scope, env, rng) for _ in range(n)]
    if integer:
        if atom:
            args = [IntLiteral(rng.choice([-1.0, -0.5, 0.0, 0.5, 1.0, 2.0])) for _ in range(n)]
        else:
            args = [gen_expr(TypeInfo("int"), scope, env, rng) for _ in range(n)]
    else:
        if atom:
            args = [FloatLiteral(rng.choice([-1.0, -0.5, 0.0, 0.5, 1.0, 2.0])) for _ in range(n)]
        else:
            args = [gen_expr(TypeInfo("float"), scope, env, rng) for _ in range(n)]

    return CallExpr(Identifier(name), args)

# This is used to generate more interesting built in types such as matrixes etc...
def gen_constructor_expr(ti: TypeInfo, scope, env, rng):
    name = ti.name

    if "vec" in name: # name.startswith("vec"):
        return gen_vector(name, scope, env, rng)

    if "mat" in name: # name.startswith("mat"):
        return gen_matrix(name, scope, env, rng)

    if name in env.struct_defs:
        fields = env.struct_defs[name]
        args = []
        for f in fields:
            fti = structfield_to_typeinfo(f)
            args.append(gen_expr(fti, scope, env, rng))
        return CallExpr(Identifier(name), args)

    return None

# ----------------------------
# Mutations: expressions
# ----------------------------

# This class is used to keep track when we have already mutated something...

class MutCtx:
    def __init__(self, budget: int):
        self.budget = budget

    def can_mutate(self) -> bool:
        return self.budget > 0

    def consume(self):
        assert self.budget > 0
        self.budget -= 1

def mutate_expr(e: Expr, rng: random.Random, scope: Scope, env: Env) -> Expr:
    """
    Returns possibly-mutated expression.
    """
    # Randomly also generate new statements...
    if coin(rng, 0.05):
        t = infer_expr_type(e, scope, env)
        return gen_expr(t, scope, env, rng, depth=1)

    # Ban comma operators... this would lead to silly statements like "srcValue(((srcValue , srcValue) , (srcValue , srcValue)))"...
    if isinstance(e, BinaryExpr) and e.op == ",":
        return e.left  # or e.right

    # Identifier replacement (type-aware)
    if isinstance(e, Identifier):
        ti = scope.lookup(e.name) or env.globals.get(e.name)
        if coin(rng, 0.20):
            pool = candidates_by_type(scope, env, ti)
            if pool:
                new_name = choose(rng, pool)
                return Identifier(new_name)
        return e

    # Literals
    if isinstance(e, IntLiteral):
        # TODO: Make sure we do not mutate the index to negative shit... aka array[-1] is invalid...
        if coin(rng, 0.30):
            delta = rng.choice([-2, -1, 1, 2, 8, -8, 16, -16])
            return IntLiteral(e.value + delta)
        return e

    if isinstance(e, FloatLiteral):
        if coin(rng, 0.30):
            # multiply / add tiny value
            if coin(rng, 0.5):
                return FloatLiteral(e.value * rng.choice([0.5, 2.0, -1.0]))
            else:
                return FloatLiteral(e.value + rng.choice([-1.0, -0.5, 0.5, 1.0]))
        return e

    if isinstance(e, BoolLiteral):
        if coin(rng, 0.30):
            return BoolLiteral(not e.value)
        return e

    # Unary
    if isinstance(e, UnaryExpr):
        op = e.op
        operand = mutate_expr(e.operand, rng, scope, env)
        if coin(rng, 0.20):
            # op = rng.choice(["+", "-", "!", "~", "++", "--"])
            # candidates = ["+", "-", "!", "~"]

            candidates = ["+", "-", "!"] # Remove the not operator which doesn't even actually exist...

            # if not is_lvalue_expr(e): # If right hand value, then add the things.
            #     candidates.extend(["--", "++"])
            op = rng.choice(candidates)
        return UnaryExpr(op, operand, postfix=e.postfix)

    # Binary
    if isinstance(e, BinaryExpr):
        # left = mutate_expr(e.left, rng, scope, env)
        lt = infer_expr_type(e.left, scope, env)
        left = mutate_expr_typed(e.left, lt, rng, scope, env)



        right = mutate_expr(e.right, rng, scope, env)
        op = e.op
        if coin(rng, 0.15):
            # keep it mostly sane: swap among common ops
            buckets = [
                ["+", "-", "*", "/"],
                ["<", "<=", ">", ">=", "==", "!="],
                ["&&", "||", "^^"],
                # ["=", "+=", "-=", "*=", "/="], # Allowing these leads to silly source code snippets like "(main()(srcValue.g) *= srcValue.g);"
            ]
            for b in buckets:
                if op in b:
                    op = rng.choice(b)
                    break
        if coin(rng, 0.10):
            # occasional operand swap
            left, right = right, left
        return BinaryExpr(op, left, right)

    # Ternary
    if isinstance(e, TernaryExpr):
        cond = mutate_expr(e.cond, rng, scope, env)
        t = mutate_expr(e.then_expr, rng, scope, env)
        f = mutate_expr(e.else_expr, rng, scope, env)
        if coin(rng, 0.10):
            t, f = f, t
        return TernaryExpr(cond, t, f)

    # Call
    if isinstance(e, CallExpr):
        callee = mutate_expr(e.callee, rng, scope, env)
        args = [mutate_expr(a, rng, scope, env) for a in e.args]

        # TODO: These next things break the calling convention too often and causes compile errors, therefore these are commented out (for now)
        '''
        if args and coin(rng, 0.15):
            rng.shuffle(args)
        if coin(rng, 0.10) and args:
            # drop or duplicate an arg sometimes
            if coin(rng, 0.5) and len(args) > 1:
                args.pop(rng.randrange(len(args)))
            else:
                args.insert(rng.randrange(len(args)+1), deepclone(rng.choice(args)))
        '''

        return CallExpr(callee, args)

    # Indexing
    if isinstance(e, IndexExpr):
        # get_indexable_length
        base = mutate_expr(e.base, rng, scope, env)
        idx = mutate_expr(e.index, rng, scope, env)
        if coin(rng, 0.20):
            # nudge constant indices
            base_t = infer_expr_type(base, scope, env)
            limit = get_indexable_length(base_t)
            if isinstance(idx, IntLiteral) and limit is not None:
                # idx = IntLiteral(idx.value + rng.choice([-1, 1, 2, -2]))
                new = idx.value + rng.choice([-1, 1])
                new = max(0, min(limit - 1, new))
                idx = IntLiteral(new)
        return IndexExpr(base, idx)

    # Member access: obj.x -> obj.y if obj is known struct/interface type
    if isinstance(e, MemberExpr):
        base = mutate_expr(e.base, rng, scope, env)
        if not isinstance(base, Identifier):
            return e # Just return the normal thing...
        # best-effort: only when base is Identifier
        if isinstance(base, Identifier):
            bti = scope.lookup(base.name) or env.globals.get(base.name)
            if bti and coin(rng, 0.35):
                fields = all_struct_field_names(env, bti.name)
                if fields and e.member in fields:
                    # pick a different field name
                    other = [x for x in fields if x != e.member]
                    if other:
                        return MemberExpr(base, choose(rng, other))
        return MemberExpr(base, e.member)

    return e


# ----------------------------
# Mutations: layouts
# ----------------------------

def mutate_int_value(v: int, rng: random.Random) -> int:
    choices = [
        0,
        1,
        -1,
        v + 1,
        v - 1,
        v * 2,
        rng.randint(-10, 10),
        rng.randint(0, 1024),
        rng.randint(0, 1 << 16),
    ]
    return rng.choice(choices)

def mutate_declarator(d, rng: random.Random):
    d = copy.deepcopy(d)

    # Rename qualifier
    if rng.random() < 0.25:
        if d.value is None:
            d.name = rng.choice(LAYOUT_NO_VALUE + LAYOUT_WITH_VALUE)
        else:
            d.name = rng.choice(LAYOUT_WITH_VALUE)

    # Mutate value
    if d.value is not None:
        # Numeric?
        try:
            iv = int(d.value)
            if rng.random() < 0.7:
                d.value = mutate_int_value(iv, rng)
        except Exception:
            # Turn garbage into integer
            if rng.random() < 0.5:
                d.value = rng.randint(-5, 100)
    else:
        # Maybe add a value illegally
        if rng.random() < 0.15:
            d.value = rng.randint(-2, 16)

    return d

def mutate_layout_qualifier(layout: LayoutQualifier, rng: random.Random) -> LayoutQualifier:
    new_layout = LayoutQualifier(declarators=[])

    # Mutate existing declarators
    for d in layout.declarators:
        if rng.random() < 0.8:
            new_layout.declarators.append(mutate_declarator(d, rng))
        else:
            new_layout.declarators.append(copy.deepcopy(d))

    # Randomly duplicate an entry (ANGLE checks this!)
    if new_layout.declarators and rng.random() < 0.2:
        new_layout.declarators.append(copy.deepcopy(rng.choice(new_layout.declarators)))

    # Randomly add a new declarator
    if rng.random() < 0.35:
        if rng.random() < 0.6:
            name = rng.choice(LAYOUT_NO_VALUE)
            new_layout.declarators.append(
                DeclaratorLayout(name=name, value=None)
            )
        else:
            name = rng.choice(LAYOUT_WITH_VALUE)
            new_layout.declarators.append(
                DeclaratorLayout(name=name, value=rng.randint(-4, 64))
            )

    # Randomly remove one
    if len(new_layout.declarators) > 1 and rng.random() < 0.15:
        del new_layout.declarators[rng.randrange(len(new_layout.declarators))]

    return new_layout

# ----------------------------
# Mutations: declarations
# ----------------------------

def mutate_array_dims(dims: List[Optional[Expr]], rng: random.Random, scope: Scope, env: Env) -> List[Optional[Expr]]:
    dims = list(dims)
    if not dims:
        if coin(rng, 0.10):
            # add one dimension sometimes
            dims.append(IntLiteral(rng.choice([1, 2, 3, 4, 8, 16])))
        return dims

    # tweak one dim
    if coin(rng, 0.25):
        k = rng.randrange(len(dims))
        if dims[k] is None:
            if coin(rng, 0.5):
                dims[k] = IntLiteral(rng.choice([1, 2, 4, 8]))
        else:
            dims[k] = mutate_expr(dims[k], rng, scope, env)

    # sometimes add/remove dims
    if coin(rng, 0.10) and len(dims) < 4:
        dims.append(IntLiteral(rng.choice([1, 2, 3, 4])))
    if coin(rng, 0.05) and len(dims) > 1:
        dims.pop(rng.randrange(len(dims)))

    return dims

# Used for mutating qualifiers of typenames primarily...

def mutate_typename(t: TypeName, rng: random.Random) -> TypeName:
    t2 = deepclone(t)

    # Exit for debugging...
    # exit(1)

    dlog("Exiting because reached mutate_typename...")
    if DEBUG:
        exit(1)

    qs = set(t2.qualifiers or [])

    # remove qualifier
    if qs and coin(rng, 0.3):
        qs.remove(rng.choice(list(qs)))

    # add storage qualifier
    if coin(rng, 0.3):
        # exit(1) # Debug exit...
        q = rng.choice(list(STORAGE_QUALIFIERS))
        qs.add(q)

    t2.qualifiers = list(qs)

    # precision is exclusive
    if coin(rng, 0.3):
        t2.precision = rng.choice(list(PRECISION_QUALIFIERS) + [None])

    return t2

def mutate_vardecl(v: VarDecl, rng: random.Random, scope: Scope, env: Env) -> VarDecl:
    v2 = deepclone(v)

    # mutate initializer
    if v2.init is not None and coin(rng, 0.35):
        v2.init = mutate_expr(v2.init, rng, scope, env)

    elif v2.init is None and coin(rng, 0.15): # TODO: Disabled for now...
        # create a simple initializer
        # (for fuzzing we don't care if types mismatch sometimes)
        # abort("Called the invalid type mutator...")
        # v2.init = rng.choice([IntLiteral(0), IntLiteral(1), FloatLiteral(1.0), BoolLiteral(True)])

        ti = vardecl_to_typeinfo(v2)
        v2.init = gen_atom(ti, scope, env, rng)

    else:
        if v2.init is None:
            ti = vardecl_to_typeinfo(v2)
            if ti.is_array(): # This is to prevent generating "int i[1] = 0;" etc
                v2.init = gen_atom(ti, scope, env, rng)
            else:
                v2.init = gen_expr(ti, scope, env, rng)

    # TODO: Here we actually mutate the qualifiers. Make this smart such that it know which variables you can add which qualifier to???
    # mutate qualifiers
    '''
    if hasattr(v2, "qualifiers") and coin(rng, 0.30):
        qs = set(v2.qualifiers or [])

        # randomly drop
        if qs and coin(rng, 0.5):
            qs.pop()

        # randomly add
        if coin(rng, 0.5):
            q = rng.choice(STORAGE_QUALIFIERS)
            if q:
                qs.add(q)

        # precision
        if coin(rng, 0.5):
            q = rng.choice(PRECISION_QUALIFIERS)
            if q:
                qs.add(q)

        v2.qualifiers = list(qs)
    '''

    if DEBUG:
        exit(1)

    if coin(rng, 0.25): # Mutate qualifiers???
        v2.type_name = mutate_typename(v2.type_name, rng)

    # mutate array dims
    if hasattr(v2, "array_dims"):
        if coin(rng, 0.25):
            v2.array_dims = mutate_array_dims(v2.array_dims, rng, scope, env)

    return v2


# ----------------------------
# Mutations: statements
# ----------------------------

def mutate_stmt(s: Stmt, rng: random.Random, scope: Scope, env: Env) -> Stmt:
    # Block introduces scope
    if isinstance(s, BlockStmt):
        child = Scope(scope)
        out_stmts: List[Stmt] = []
        '''
        for st in s.stmts:
            out_stmts.append(mutate_stmt(st, rng, child, env))

            # Occasionally insert an extra harmless stmt
            if coin(rng, 0.10):
                # out_stmts.append(ExprStmt(IntLiteral(rng.randrange(10))))
                sd = gen_struct_vardecl(child, env, rng)
                if sd:
                    out_stmts.append(sd)
        '''

        out_stmts = copy.deepcopy(s.stmts)
        if out_stmts:
            rand_ind = rng.randrange(len(out_stmts))
            out_stmts[rand_ind] = mutate_stmt(out_stmts[rand_ind], rng, child, env)
            if coin(rng, 0.10):
                sd = gen_struct_vardecl(child, env, rng)
                if sd:
                    out_stmts.insert(rng.randrange(len(out_stmts)+1), sd)
        # Add a new expression too maybe???
        if coin(rng, 0.30):
            '''
            want = TypeInfo("int")
            expr = gen_expr(want, child, env, rng)
            out_stmts.append(ExprStmt(expr))
            '''


            # Maybe something like this here???

            e = gen_expr(None, child, env, rng)
            if has_side_effect(e):
                out_stmts.append(ExprStmt(e))

            # out_stmts.append(gen_assignment_stmt(child, env, rng))

        # shuffle within block rarely (can break semantics but fine for fuzzing)
        if len(out_stmts) > 2 and coin(rng, 0.05):
            rng.shuffle(out_stmts)

        return BlockStmt(out_stmts)

    if isinstance(s, DeclStmt):
        # define vars into scope, and mutate decls
        '''
        new_decls = []
        for d in s.decls:
            d2 = mutate_vardecl(d, rng, scope, env)
            new_decls.append(d2)
            # register in scope
            scope.define(d2.name, vardecl_to_typeinfo(d2))
        '''

        new_decls = []
        mut_i = rng.randrange(len(s.decls)) if s.decls else None

        for i, d in enumerate(s.decls):
            if i == mut_i:
                d2 = mutate_vardecl(d, rng, scope, env)
            else:
                d2 = d  # reuse original object (or deepclone if needed)

            new_decls.append(d2)
            scope.define(d2.name, vardecl_to_typeinfo(d2))

        # maybe reorder decl list
        if len(new_decls) > 1 and coin(rng, 0.10):
            rng.shuffle(new_decls)
        return DeclStmt(new_decls)

    if isinstance(s, ExprStmt):
        return ExprStmt(mutate_expr(s.expr, rng, scope, env))

    if isinstance(s, IfStmt):
        if coin(rng, 0.10): # Generate new thing...
            return gen_if(scope, env, rng)
        cond = mutate_expr(s.cond, rng, scope, env)
        thenb = mutate_stmt(s.then_branch, rng, Scope(scope), env)
        elseb = mutate_stmt(s.else_branch, rng, Scope(scope), env) if s.else_branch else None
        if elseb and coin(rng, 0.05):
            thenb, elseb = elseb, thenb
        return IfStmt(cond, thenb, elseb)

    if isinstance(s, WhileStmt):
        cond = mutate_expr(s.cond, rng, scope, env)
        body = mutate_stmt(s.body, rng, Scope(scope), env)
        return WhileStmt(cond, body)

    if isinstance(s, DoWhileStmt):
        body = mutate_stmt(s.body, rng, Scope(scope), env)
        cond = mutate_expr(s.cond, rng, scope, env)
        return DoWhileStmt(body, cond)

    if isinstance(s, ForStmt):
        child = Scope(scope)
        init = mutate_stmt(s.init, rng, child, env) if s.init else None
        cond = mutate_expr(s.cond, rng, child, env) if s.cond else None
        loop = mutate_expr(s.loop, rng, child, env) if s.loop else None
        body = mutate_stmt(s.body, rng, child, env)
        return ForStmt(init, cond, loop, body)

    if isinstance(s, ReturnStmt):
        if s.expr is None:
            return s
        return ReturnStmt(mutate_expr(s.expr, rng, scope, env))

    if isinstance(s, (BreakStmt, ContinueStmt, DiscardStmt, EmptyStmt)):
        return s

    # Switch / case / default (your AST uses plain classes, not dataclasses)
    if isinstance(s, SwitchStmt):
        if coin(rng, 0.10): # Generate new thing...
            return gen_switch(scope, env, rng)
        expr = mutate_expr(s.expr, rng, scope, env)
        body = mutate_stmt(s.body, rng, Scope(scope), env)
        return SwitchStmt(expr, body)

    if isinstance(s, CaseStmt):
        expr = mutate_expr(s.expr, rng, scope, env)
        child = Scope(scope)
        stmts = [mutate_stmt(x, rng, child, env) for x in s.stmts]
        return CaseStmt(expr, stmts)

    if isinstance(s, DefaultStmt):
        assert False
        child = Scope(scope)
        stmts = [mutate_stmt(x, rng, child, env) for x in s.stmts]
        return DefaultStmt(stmts)

    return s


# ----------------------------
# Mutations: struct definitions
# ----------------------------

def mutate_struct_fields(fields: List[StructField], rng: random.Random, scope: Scope, env: Env) -> List[StructField]:
    fields2 = deepclone(fields)

    # reorder fields sometimes
    if len(fields2) > 1 and coin(rng, 0.10):
        rng.shuffle(fields2)

    # rename one field sometimes (can break users; that’s ok for fuzzing)
    if fields2 and coin(rng, 0.08):
        f = fields2[rng.randrange(len(fields2))]
        f.name = f.name + rng.choice(["_", "0", "1", "x", "y"])

    # mutate one field array size/dims
    if fields2 and coin(rng, 0.20):
        f = fields2[rng.randrange(len(fields2))]
        # support either array_size or array_dims if you later add it
        if hasattr(f, "array_dims") and f.array_dims is not None:
            f.array_dims = mutate_array_dims(f.array_dims, rng, scope, env)
        else:
            if f.array_size is None:
                # TODO: Generate the array size expression instead???
                if coin(rng, 0.5):
                    f.array_size = IntLiteral(rng.choice([1, 2, 4, 8, 16]))
            else:
                f.array_size = mutate_expr(f.array_size, rng, scope, env)

    return fields2


# ----------------------------
# Mutations: top-level
# ----------------------------

def mutate_toplevel(item: TopLevel, rng: random.Random, env: Env) -> TopLevel:

    dlog("item: "+str(item))

    # StructDef
    if isinstance(item, StructDef):
        dlog("mutating struct definition")
        # if DEBUG:
        #     exit(1)
        # dexit()
        # mutate fields
        dummy_scope = Scope(None)
        new_fields = mutate_struct_fields(item.fields, rng, dummy_scope, env)
        it = deepclone(item)
        it.fields = new_fields
        # update env (so member mutations later can use new field lists)
        env.struct_defs[it.name] = list(it.fields)
        return it

    # StructDecl: struct foo {..} a,b;
    if isinstance(item, StructDecl):

        # dlog("item: "+str(item))
        # dlog("item.declarators[0]: "+str(item.declarators[0]))
        # dexit(msg="StructDecl")

        # [DEBUG] item: StructDecl(struct_type=StructType(name='S1', members=[StructField(type_name=TypeName(name='samplerCube', precision=None, qualifiers=[]), name='ar', array_size=[])]), declarators=[<shader_ast.Declarator object at 0x7f3aaa261b70>])
        it = deepclone(item)
        dummy_scope = Scope(None)
        it.struct_type.members = mutate_struct_fields(it.struct_type.members, rng, dummy_scope, env)


        # 🔥 THIS IS THE IMPORTANT PART 🔥
        # if it.declarators and coin(rng, 0.35):
        if coin(rng, 0.50):
            d = rng.choice(it.declarators)

            old = list(d.qualifiers)
            dlog("stuff")
            mutate_declarator_qualifiers(
                d,
                rng,
                storage_pool=["uniform", "buffer", "const", None],
                precision_pool=PRECISION_QUALIFIERS,
            )

            # optional debug / assert-chasing hook
            # if "uniform" in d.qualifiers and "uniform" not in old:
            #     global stop
            #     stop = True


        # mutate declarators
        if it.declarators and coin(rng, 0.10):
            rng.shuffle(it.declarators)
        if it.declarators and coin(rng, 0.20):
            d = it.declarators[rng.randrange(len(it.declarators))]
            if d.array_size is not None:
                d.array_size = mutate_expr(d.array_size, rng, dummy_scope, env)

        # update env if named
        if it.struct_type.name:
            env.struct_defs[it.struct_type.name] = list(it.struct_type.members)

        return it

    # InterfaceBlock
    if isinstance(item, InterfaceBlock):
        it = deepclone(item)
        dummy_scope = Scope(None)
        members = _flatten_members(it.members)
        members = mutate_struct_fields(members, rng, dummy_scope, env)
        it.members = members  # normalize flat

        # maybe toggle instance name
        if coin(rng, 0.05):
            if it.instance:
                it.instance = None
            else:
                it.instance = it.name + "_inst"

        # update env
        env.interface_blocks[it.name] = list(it.members)
        if it.instance:
            env.globals[it.instance] = TypeInfo(it.name, [])
        return it

    # GlobalDecl
    if isinstance(item, GlobalDecl):
        it = deepclone(item)
        dummy_scope = Scope(None)
        it.decls = [mutate_vardecl(d, rng, dummy_scope, env) for d in it.decls]
        if len(it.decls) > 1 and coin(rng, 0.10):
            rng.shuffle(it.decls)
        for d in it.decls:
            env.globals[d.name] = vardecl_to_typeinfo(d)
        return it

    # FunctionDef
    if isinstance(item, FunctionDef):
        # TODO: Add qualifier mutation. Maybe something like the following? :
        '''
        for p in it.params:
            if coin(rng, 0.25):
                p.qualifier = rng.choice(PARAM_QUALIFIERS)
        '''

        it = deepclone(item)

        # build function scope with params
        fscope = Scope(None)
        for p in it.params:
            fscope.define(p.name, typename_to_typeinfo(p.type_name))

        # mutate body
        it.body = mutate_stmt(it.body, rng, fscope, env)

        # maybe reorder params sometimes
        if len(it.params) > 1 and coin(rng, 0.05):
            rng.shuffle(it.params)

        for p in it.params:
            if coin(rng, 0.25):
                # global stop
                # stop = True
                p.type_name = mutate_typename(p.type_name, rng)

        return it

    # TODO: Make this layout mutations better maybe???

    if isinstance(item, LayoutQualifier):

        # global stop
        # stop = True
        it = mutate_layout_qualifier(item, rng)
        # break here...
        # global stop
        # stop = True
        return it

    # Declaration (your old mixed top-level type)
    if isinstance(item, Declaration):
        it = deepclone(item)
        dummy_scope = Scope(None)
        # mutate declarators a bit
        if it.declarators and coin(rng, 0.10):
            rng.shuffle(it.declarators)
        for d in it.declarators:
            if d.init is not None and coin(rng, 0.25):
                d.init = mutate_expr(d.init, rng, dummy_scope, env)
        return it

    # TODO add function declarations here too...

    return item

from special_mutations import *

# ----------------------------
# Public entrypoint
# ----------------------------

DEBUG_STOP = False

def debug_source(tu, tu2): # Debug the stuff here...
    # exit(0)
    if DEBUG_STOP:
        # exit(0)
        if stop:
            # exit(0)
            try:
                result = shader_unparser.unparse_tu(tu2) # Unparse that shit...
            except Exception as e:
                # ???
                print(e)
                exit(1)
            # Now print the thing...
            print("Mutated source code when hit the thing: "+str(result))
            print("Original code was this here: "+str(shader_unparser.unparse_tu(tu)))
            exit(0)

def mutate_translation_unit(tu: TranslationUnit, rng: random.Random) -> TranslationUnit:

    # Call the mutation...

    if coin(rng, 0.1) : # Debugging for the full rewrite stuff...
        return mutate_translation_unit_full(tu, rng)

    """
    High-level mutator: collects env then mutates items.
    Returns a NEW TranslationUnit.
    """
    # tu2 = deepclone(tu)
    tu2 = tu # Use the reference...
    env = build_env(tu2)

    # Mutate each item; keep env updated as we go.
    new_items: List[TopLevel] = []
    # for item in tu2.items:
    #     new_items.append(mutate_toplevel(item, rng, env))

    # Instead of mutating each expression, just mutate a randomly chosen one...

    #new_items = copy.deepcopy(tu2.items) # Copy...

    new_items = tu2.items # Just use the reference. Do not copy them...

    # Check for the special havoc mode.

    if coin(rng, 0.10): # 10 percent chance of special havoc mode...
        mutated_items, stop2 = special_havoc(new_items, rng, env)
        tu2.items = mutated_items
        '''
        global DEBUG_STOP
        global stop
        if stop2:
            DEBUG_STOP = 1

            stop = stop2
        debug_source(tu, tu2) # Debug that stuff...
        '''


        return tu2 # Return the mutated structure...


    # Now get one...

    ind = rng.randrange(len(new_items))

    # Now pop that ...

    item = new_items.pop(ind)

    # Mutate

    item = mutate_toplevel(item, rng, env)

    # Now add that back...

    new_items.insert(ind, item)

    # Structural additions etc...

    # Add struct?
    if coin(rng, 0.02):
        gen_struct_definition(new_items, rng, env)

    # occasional top-level reorder (dangerous but good for fuzzing)
    if len(new_items) > 2 and coin(rng, 0.03):
        rng.shuffle(new_items)

    if coin(rng, 0.10) and env.struct_defs:
        sname = rng.choice(list(env.struct_defs.keys()))
        vname = f"g_{rng.randrange(10000)}"
        init = gen_constructor_expr(TypeInfo(sname), Scope(None), env, rng)

        decl = GlobalDecl([
            VarDecl(
                TypeName(sname),
                vname,
                init=init,
                array_dims=[]
            )
        ])

        # 🔴 FIND STRUCT DEF LOCATION
        idx = find_struct_def_index(new_items, sname)

        if idx is not None:
            # insert immediately AFTER struct definition
            new_items.insert(idx + 1, decl)
        else:
            # fallback (should be rare)
            # assert False
            new_items.insert(0, decl)

        env.globals[vname] = TypeInfo(sname)
        # global stop
        # stop = True

    tu2.items = new_items

    # Now try to unparse that shit...
    # exit(1)
    # if DEBUG:
    # return tu2 # Short circuit here...
    debug_source(tu, tu2)


    return tu2









def mutate_translation_unit_full(tu: TranslationUnit, rng: random.Random) -> TranslationUnit:
    """
    Aggressive mutator: mutates ALL top-level items.
    Still uses env tracking.
    Returns a NEW TranslationUnit.
    """

    tu2 = deepclone(tu)
    env = build_env(tu2)

    new_items: List[TopLevel] = []

    for item in tu2.items:
        mutated = mutate_toplevel(item, rng, env)
        new_items.append(mutated)

    # Structural additions

    # Add new struct definitions more often
    if coin(rng, 0.15):
        gen_struct_definition(new_items, rng, env)

    # Add new global struct instance
    if coin(rng, 0.20) and env.struct_defs:
        sname = rng.choice(list(env.struct_defs.keys()))
        vname = f"g_{rng.randrange(10000)}"
        init = gen_constructor_expr(TypeInfo(sname), Scope(None), env, rng)

        decl = GlobalDecl([
            VarDecl(
                TypeName(sname),
                vname,
                init=init,
                array_dims=[]
            )
        ])

        new_items.insert(rng.randrange(len(new_items)+1), decl)
        env.globals[vname] = TypeInfo(sname)

    # Top-level reorder more aggressively
    if len(new_items) > 2 and coin(rng, 0.20):
        rng.shuffle(new_items)

    tu2.items = new_items
    return tu2
and here is the parser thing here:
`# shader_parser.py
from __future__ import annotations
from typing import List, Optional, Union

from shader_lexer import Token, lex
from shader_ast import *
from const import *
from collections.abc import Iterable

import random

class ParseError(Exception):
    pass

DEBUG = True

# False for now...
SAVE_FAILURES = False

current_input = None

def save_failure(shader_source, name, error_message):
    fh = open(str(name)+"_"+str(random.randrange(1000000)), "w")
    fh.write(shader_source)
    fh.write("\n\n\n\n")
    fh.write(error_message)
    fh.close()
    return

class Parser:
    def __init__(self, tokens: List[Token], original_input=None):
        self.toks = tokens
        self.i = 0
        if original_input != None:
            self.original_input = original_input

    def peek(self) -> Token:
        return self.toks[self.i]

    def advance(self) -> Token:
        t = self.toks[self.i]
        self.i += 1
        return t

    def match(self, kind: str, value: Optional[str] = None) -> bool:
        t = self.peek()
        if t.kind == kind:
            if value is None or t.value == value:
                self.advance()
                return True
        # punctuation encoded as kind==value, e.g. kind="{" value="{"
        if value is None and t.kind == kind and t.value == kind:
            self.advance()
            return True
        if value is not None and t.kind == kind and t.value == value:
            self.advance()
            return True
        return False

    def expect(self, kind: str, value: Optional[str] = None) -> Token:
        t = self.peek()
        if value is None:
            if t.kind == kind or (t.kind == kind and t.value == kind):
                return self.advance()
        else:
            if (t.kind == kind and t.value == value) or (t.kind == value and t.value == value):
                return self.advance()
        if DEBUG:
            print("Got failure here: "+str(current_input[t.pos:t.pos+100]))
            if SAVE_FAILURES:
                try:
                    save_failure(self.original_input, "failure", f"Expected {kind} {value or ''} at {t.pos}, got {t.kind}:{t.value}")
                except Exception as e:
                    print("!"*100)
                    print(e)
        raise ParseError(f"Expected {kind} {value or ''} at {t.pos}, got {t.kind}:{t.value}")

    # -----------------------
    # Expression parsing (Pratt)
    # -----------------------

    # This is a helper for parsing inline struct definitions...

    def _looks_like_struct_decl_stmt(self) -> bool:
        j = self.i

        # Skip qualifiers like const, in, out, uniform, etc.
        while j < len(self.toks):
            t = self.toks[j]
            if t.kind == "KW" and t.value in QUALIFIERS:
                j += 1
                continue
            break

        # Now must see 'struct'
        return j < len(self.toks) and self.toks[j].kind == "KW" and self.toks[j].value == "struct"

    # This function basically just skips over the layout things. We do not currently support them in the thing...
    def parse_layout_qualifier(self):
        # assumes current token is 'layout'
        self.advance()              # 'layout'
        self.expect("(")
        depth = 1
        while depth > 0:
            t = self.advance()
            if t.kind == "(":
                depth += 1
            elif t.kind == ")":
                depth -= 1

    def parse_expr(self, min_prec: int = 0) -> Expr:
        left = self.parse_prefix()

        while True:
            t = self.peek()
            if t.kind == "OP" and t.value in ("++", "--"):
                # postfix binds very tightly
                if PRECEDENCE["CALL"] < min_prec:
                    break
                op = self.advance().value
                left = UnaryExpr(op, left, postfix=True)
                continue

            # postfix: call
            if t.kind == "(":
                if PRECEDENCE["CALL"] < min_prec:
                    break
                left = self.parse_call(left)
                continue

            # postfix: indexing
            if t.kind == "[":
                if PRECEDENCE["INDEX"] < min_prec:
                    break
                left = self.parse_index(left)
                continue

            # postfix: member access (.)
            if t.kind == "OP" and t.value == ".":
                if PRECEDENCE["."] < min_prec:
                    break
                self.advance()
                ident = self.expect("ID")  # swizzle/field
                left = MemberExpr(left, ident.value)
                continue

            # ternary
            if t.kind == "OP" and t.value == "?":
                if 0 < min_prec:  # ternary is very low-ish; only parse if allowed
                    break
                self.advance()
                then_expr = self.parse_expr(0)
                self.expect("OP", ":")
                else_expr = self.parse_expr(0)
                left = TernaryExpr(left, then_expr, else_expr)
                continue

            # binary op
            if t.kind == "OP" and t.value in PRECEDENCE:
                op = t.value
                prec = PRECEDENCE[op]
                if prec < min_prec:
                    break
                self.advance()
                next_min = prec + (0 if op in RIGHT_ASSOC else 1)
                right = self.parse_expr(next_min)
                left = BinaryExpr(op, left, right)
                continue

            # sequence comma operator (treat as binary)
            if t.kind == ",":
                op = ","
                prec = PRECEDENCE[op]
                if prec < min_prec:
                    break
                self.advance()
                right = self.parse_expr(prec + 1)
                left = BinaryExpr(op, left, right)
                continue

            break

        return left

    def parse_declarator_list(self, base_type):
        decls = []
        while True:
            name = self.expect("ID").value

            array_size = None
            if self.match("["):
                if not self.match("]"):
                    array_size = self.parse_expr(0)
                    self.expect("]")

            init = None
            # if self.match("="):
            #     init = self.parse_expr(0)

            if self.peek().kind == "OP" and self.peek().value == "=":
                self.advance()
                init = self.parse_expr(0)
                # init = self.parse_expr(PRECEDENCE[","] + 1)
                if self.peek().kind == ",":
                    pass

            decls.append(Declarator(name, base_type, array_size, init))

            if not self.match(","):
                break
        return decls

    def parse_prefix(self) -> Expr:
        t = self.peek()

        # parenthesized
        if t.kind == "(":
            self.advance()
            e = self.parse_expr(0)
            self.expect(")")
            return e

        # literals
        if t.kind == "INT":
            self.advance()
            s = t.value.lower()
            unsigned = False
            if s.endswith("u"):
                unsigned = True
                s = s[:-1]

            if s.startswith("0x"):
                val = int(s, 16)
            elif s.startswith("0") and len(s) > 1:
                val = int(s, 8)
            else:
                val = int(s, 10)

            return IntLiteral(val)

        if t.kind == "FLOAT":
            self.advance()
            s = t.value.rstrip("fFlL")
            return FloatLiteral(float(s))

        if t.kind == "KW" and t.value in ("true", "false"):
            self.advance()
            return BoolLiteral(t.value == "true")

        # unary
        if t.kind == "OP" and t.value in ("+", "-", "!", "~", "++", "--"):
            op = self.advance().value
            # operand = self.parse_expr(PRECEDENCE["*"])  # unary binds fairly tightly
            operand = self.parse_expr(PRECEDENCE["CALL"])
            return UnaryExpr(op, operand, postfix=False)

        # identifier
        if t.kind in ("ID", "KW"):
            # allow keywords as identifiers sometimes (GLSL constructors/types)
            self.advance()
            return Identifier(t.value)

        raise ParseError(f"Unexpected token in expression at {t.pos}: {t.kind}:{t.value}")

    def parse_call(self, callee: Expr) -> Expr:
        self.expect("(")
        args: List[Expr] = []
        if not self.match(")"):
            while True:
                args.append(self.parse_expr(0))
                if self.match(")"):
                    break
                self.expect(",")
        return CallExpr(callee, args)

    def parse_index(self, base: Expr) -> Expr:
        self.expect("[")
        idx = self.parse_expr(0)
        self.expect("]")
        return IndexExpr(base, idx)

    # -----------------------
    # Types / Decls
    # -----------------------

    def parse_type_name(self) -> TypeName:
        qualifiers: List[str] = []
        precision: Optional[str] = None

        while True:
            t = self.peek()
            if t.kind == "KW" and t.value in QUALIFIERS:
                qualifiers.append(self.advance().value)
                continue
            if t.kind == "KW" and t.value in PRECISIONS:
                precision = self.advance().value
                continue
            break

        # type identifier or built-in keyword
        t = self.peek()
        if t.kind == "KW" and t.value in TYPELIKE_KEYWORDS:
            name = self.advance().value
            return TypeName(name=name, precision=precision, qualifiers=qualifiers)

        if t.kind == "ID":
            name = self.advance().value
            return TypeName(name=name, precision=precision, qualifiers=qualifiers)
        if DEBUG:
            print("Got error here: "+str(current_input[t.pos:t.pos+100])) # Print for debugging the thing...
            if SAVE_FAILURES:
                save_failure(self.original_input, "error", f"Expected type name at {t.pos}, got {t.kind}:{t.value}")
        raise ParseError(f"Expected type name at {t.pos}, got {t.kind}:{t.value}")

    def parse_struct_member(self) -> list[StructField]:
        # NEW: skip optional layout qualifiers
        # TODO: Support layouts inside struct members???
        while self.peek().kind == "KW" and self.peek().value == "layout":
            self.parse_layout_qualifier()

        tname = self.parse_type_name()
        fields = []

        while True:
            name = self.expect("ID").value

            array_dims = []
            while self.match("["):
                if not self.match("]"):
                    array_dims.append(self.parse_expr(0))
                    self.expect("]")
                else:
                    array_dims.append(None)

            fields.append(StructField(tname, name, array_dims))

            if not self.match(","):
                break

        self.expect(";")
        return fields

    def parse_var_decl(self, type_name: TypeName) -> VarDecl:
        name = self.expect("ID").value

        array_dims = []
        while self.match("["):
            if self.match("]"):
                array_dims.append(None)
            else:
                array_dims.append(self.parse_expr(0))
                self.expect("]")

        init = None
        if self.match("OP", "="):
            init = self.parse_expr(0)
            # init = self.parse_expr(PRECEDENCE[","] + 1)
            if self.peek().kind == ",":
                pass

        return VarDecl(type_name, name, array_dims, init)

    def parse_struct_specifier(self):
        self.expect("KW", "struct")

        name = None
        if self.peek().kind == "ID":
            name = self.advance().value

        self.expect("{")
        members = []

        while not self.match("}"):
            fields = self.parse_struct_member()
            members.extend(fields)   # ✅ always safe now

        return StructType(name, members)

    def parse_decl_stmt(self) -> DeclStmt:
        if self.peek().value == "struct":
            struct_type = self.parse_struct_specifier()

            declarators = []
            if self.peek().kind == "ID":
                declarators = self.parse_declarator_list(struct_type)

            self.expect(";")
            return Declaration(struct_type, declarators)

        tname = self.parse_type_name()
        decls: List[VarDecl] = [self.parse_var_decl(tname)]
        while self.match(","):
            decls.append(self.parse_var_decl(tname))
        self.expect(";")
        return DeclStmt(decls)

    def parse_case_stmt(self) -> CaseStmt:
        self.expect("ID", "case")
        expr = self.parse_expr(0)
        # We need to get rid of this here...
        # self.expect(":")
        self.advance() # Consume the ":"
        stmts = []

        while True:
            t = self.peek()
            if (t.value in ("case", "default")) or t.kind == "}":
                break
            stmts.append(self.parse_stmt())

        return CaseStmt(expr, stmts)


    def parse_default_stmt(self) -> DefaultStmt:
        self.expect("ID", "default")
        # We need to get rid of this here...
        # self.expect(":")
        self.advance() # Consume the ":"
        stmts = []

        while True:
            t = self.peek()
            # if (t.kind == "KW" and t.value in ("case", "default")) or t.kind == "}":
            if (t.value in ("case", "default")) or t.kind == "}":
                break
            stmts.append(self.parse_stmt())

        return DefaultStmt(stmts)

    # -----------------------
    # Switch statements
    # -----------------------

    def parse_switch_block(self) -> BlockStmt:
        self.expect("{")
        stmts = []

        while not self.match("}"):
            t = self.peek()

            if t.value == "case":
                stmts.append(self.parse_case_stmt())
                continue

            if t.value == "default":
                stmts.append(self.parse_default_stmt())
                continue

            # statements inside a case
            stmts.append(self.parse_stmt())

        return BlockStmt(stmts)

    # -----------------------
    # Statements
    # -----------------------

    def parse_stmt(self) -> Stmt:
        t = self.peek()

        # switch statements
        if t.value == "switch": # This originally was t.kind == "KW"
            self.advance()
            self.expect("(")
            expr = self.parse_expr(0)
            self.expect(")")
            body = self.parse_switch_block()
            return SwitchStmt(expr, body)


        # block
        if t.kind == "{":
            return self.parse_block()

        # struct definition inside a block (???)
        # if t.kind == "KW" and t.value == "struct": # TODO: This check here fails, because struct definitions can have "const" in the front of it etc..
        if self._looks_like_struct_decl_stmt():
            struct_decl = self.parse_struct_toplevel_decl()
            return struct_decl

        # empty
        if t.kind == ";":
            self.advance()
            return EmptyStmt()

        # if
        if t.kind == "KW" and t.value == "if":
            self.advance()
            self.expect("(")
            cond = self.parse_expr(0)
            self.expect(")")
            then_branch = self.parse_stmt()
            else_branch = None
            if self.peek().kind == "KW" and self.peek().value == "else":
                self.advance()
                else_branch = self.parse_stmt()
            return IfStmt(cond, then_branch, else_branch)

        # while
        if t.kind == "KW" and t.value == "while":
            self.advance()
            self.expect("(")
            cond = self.parse_expr(0)
            self.expect(")")
            body = self.parse_stmt()
            return WhileStmt(cond, body)

        # do-while
        if t.kind == "KW" and t.value == "do":
            self.advance()
            body = self.parse_stmt()
            self.expect("KW", "while")
            self.expect("(")
            cond = self.parse_expr(0)
            self.expect(")")
            self.expect(";")
            return DoWhileStmt(body, cond)

        # for
        if t.kind == "KW" and t.value == "for":
            self.advance()
            self.expect("(")
            init: Optional[Union[DeclStmt, ExprStmt]] = None

            # init can be decl, expr, or empty
            if self.peek().kind != ";":
                if self._looks_like_decl():
                    init = self.parse_decl_stmt()
                else:
                    e = self.parse_expr(0)
                    self.expect(";")
                    init = ExprStmt(e)
            else:
                self.expect(";")

            cond: Optional[Expr] = None
            if self.peek().kind != ";":
                cond = self.parse_expr(0)
            self.expect(";")

            loop: Optional[Expr] = None
            if self.peek().kind != ")":
                loop = self.parse_expr(0)
            self.expect(")")

            body = self.parse_stmt()
            return ForStmt(init, cond, loop, body)

        # jump statements
        if t.kind == "KW" and t.value == "return":
            self.advance()
            if self.peek().kind == ";":
                self.advance()
                return ReturnStmt(None)
            e = self.parse_expr(0)
            self.expect(";")
            return ReturnStmt(e)

        if t.kind == "KW" and t.value == "break":
            self.advance()
            self.expect(";")
            return BreakStmt()

        if t.kind == "KW" and t.value == "continue":
            self.advance()
            self.expect(";")
            return ContinueStmt()

        if t.kind == "KW" and t.value == "discard":
            self.advance()
            self.expect(";")
            return DiscardStmt()

        # declaration vs expression statement
        if self._looks_like_decl():
            return self.parse_decl_stmt()

        # expression statement
        e = self.parse_expr(0)
        self.expect(";")
        return ExprStmt(e)

    def parse_block(self) -> BlockStmt:
        self.expect("{")
        stmts: List[Stmt] = []
        while self.peek().kind != "}":
            if self.peek().kind == "EOF":
                raise ParseError("Unexpected EOF in block")
            stmts.append(self.parse_stmt())
        self.expect("}")
        return BlockStmt(stmts)

    def _looks_like_decl(self) -> bool:
        """
        Heuristic: qualifiers/precision/type then identifier.
        This is not perfect GLSL disambiguation but good enough for fuzzing.
        """
        j = self.i
        # skip qualifiers/precision
        while j < len(self.toks):
            t = self.toks[j]
            if t.kind == "KW" and (t.value in QUALIFIERS or t.value in PRECISIONS):
                j += 1
                continue
            break
        if j >= len(self.toks):
            return False
        t = self.toks[j]
        # type can be builtin keyword or identifier (user-defined struct type)
        # if not ((t.kind == "KW" and t.value in TYPELIKE_KEYWORDS) or t.kind == "ID"):
        #     return False

        # The previous codeblock didn't handle inline structs properly, therefore put the thing here...


        if not (
            (t.kind == "KW" and t.value in TYPELIKE_KEYWORDS)
            or t.kind == "ID"
            # or (t.kind == "KW" and t.value == "struct")
        ):
            return False


        # next must exist and be an identifier (var name) or '(' (function)
        if j + 1 >= len(self.toks):
            return False

        # This is to handle potential functions that returns an array...
        j2 = j + 1
        while j2 < len(self.toks) and self.toks[j2].kind == "[":
            j2 += 1
            if j2 < len(self.toks) and self.toks[j2].kind != "]":
                j2 += 1
            if j2 < len(self.toks) and self.toks[j2].kind == "]":
                j2 += 1

        if j2 >= len(self.toks):
            return False

        return self.toks[j2].kind == "ID"

        # t2 = self.toks[j + 1]
        # return t2.kind == "ID"

    # -----------------------
    # Top-level parsing
    # -----------------------

    def parse_struct_toplevel_decl(self):
        qualifiers = []
        while self.peek().kind == "KW" and self.peek().value in QUALIFIERS:
            # print("self.peek().kind: "+str(self.peek().kind))
            # print("self.peek().kind: "+str(self.peek().value))
            qualifiers.append(self.advance().value)

        struct_type = self.parse_struct_specifier()

        declarators = []
        if self.peek().kind != ";":
            declarators = self.parse_declarator_list(struct_type)
            for d in declarators:
                d.qualifiers = qualifiers.copy()

        self.expect(";")
        return StructDecl(struct_type, declarators)

    def parse_struct_def(self) -> StructDef:
        self.expect("KW", "struct")
        name = self.expect("ID").value
        self.expect("{")
        fields: List[StructField] = []
        while self.peek().kind != "}":
            tname = self.parse_type_name()
            fname = self.expect("ID").value
            arr: Optional[Expr] = None
            if self.match("["):
                if not self.match("]"):
                    arr = self.parse_expr(0)
                    self.expect("]")
            self.expect(";")
            fields.append(StructField(tname, fname, arr))
        self.expect("}")
        self.expect(";")
        return StructDef(name, fields)

    def parse_function_def_or_decl(self) -> FunctionDef:
        ret = self.parse_type_name()

        # parse array dimensions on return type
        array_dims = []
        while self.match("["):
            if self.match("]"):
                array_dims.append(None)
            else:
                array_dims.append(self.parse_expr(0))
                self.expect("]")

        if array_dims:
            ret = TypeName(
                name=ret.name,
                precision=ret.precision,
                qualifiers=ret.qualifiers,
                array_dims=array_dims
            )

        fname = self.expect("ID").value
        self.expect("(")
        params: List[FunctionParam] = []
        if not self.match(")"):
            while True:
                '''
                ptype = self.parse_type_name()
                pname = self.expect("ID").value
                parr: Optional[Expr] = None
                if self.match("["):
                    if not self.match("]"):
                        parr = self.parse_expr(0)
                        self.expect("]")
                '''

                ptype = self.parse_type_name()

                # Parameter name is OPTIONAL
                pname = None
                if self.peek().kind == "ID":
                    pname = self.expect("ID").value

                parr = None
                if self.match("["):
                    if not self.match("]"):
                        parr = self.parse_expr(0)
                        self.expect("]")
                params.append(FunctionParam(ptype, pname, parr))
                if self.match(")"):
                    break
                self.expect(",")
        # Declaration or definition?
        if self.peek().kind == "{": # Function definition (normal route...)
            body = self.parse_block()
            return FunctionDef(ret, fname, params, body)
        else:
            self.expect(";") # The semicolon after the declaration...
            return FunctionDecl(ret, fname, params)

    def _looks_like_interface_block(self) -> bool:
        j = self.i
        # storage qualifier
        if self.toks[j].value not in ("uniform", "in", "out", "buffer"):
            return False
        j += 1
        # block name
        if j >= len(self.toks) or self.toks[j].kind != "ID":
            return False
        j += 1
        # must be followed by '{'
        return j < len(self.toks) and self.toks[j].kind == "{"

    def parse_interface_block(self) -> InterfaceBlock:
        storage = self.advance().value          # uniform / in / out / buffer
        name = self.expect("ID").value

        self.expect("{")
        members = []
        while self.peek().kind != "}":
            members.append(self.parse_struct_member())
        self.expect("}")

        # This next snippet of code doesn't support arrays
        '''
        instance = None
        if self.peek().kind == "ID":
            instance = self.advance().value

        self.expect(";")
        return InterfaceBlock(storage, name, members, instance)
        '''

        instance = None
        array_dims = []

        if self.peek().kind == "ID":
            instance = self.advance().value

            # ---- NEW: parse optional array dimensions ----
            while self.match("["):
                if self.match("]"):
                    array_dims.append(None)
                else:
                    array_dims.append(self.parse_expr(0))
                    self.expect("]")

        self.expect(";")
        return InterfaceBlock(storage, name, members, instance, array_dims)

    def parse_global_decl(self) -> GlobalDecl:
        # parse type then one or more var decls then ;
        tname = self.parse_type_name()
        decls: List[VarDecl] = [self.parse_var_decl(tname)]
        while self.match(","):
            decls.append(self.parse_var_decl(tname))
        self.expect(";")
        return GlobalDecl(decls)

    '''
    class DeclaratorLayout:
    def __init__(self, name, value = None): # If value is None, then this qualifier thing doesn't need a value for example "std140" if value is not None, then for example "location=0" is emitted, these objects are then joined with a comma to become layout(std140, location=0) etc...
        self.name = name
        self.value = value

    # This is a special case, since this is a toplevel expression that doesn't end in a newline...
    @dataclass
    class LayoutQualifier(TopLevel):
        declarators: List[DeclaratorLayout]
    '''

    def parse_layout(self):
        # Now try to parse the layout...
        self.expect("KW", "layout") # Get the layout, then do the stuff...
        self.expect("(") # opening paranthesis
        decls = [] # Initialize declarator list...
        while self.peek().kind == "ID":
            # Check if name or name=value thing...
            name = self.advance().value
            # Now check for the equal sign...
            if self.peek().value == "=":
                self.advance() # Eat the equal sign...
                value = self.advance().value
                obj = DeclaratorLayout(name, value=value)
                decls.append(obj)
                # Now check for the comma or paranthesis
                if self.peek().value == ",":
                    self.advance()
                    continue
                elif self.peek().value == ")": # Close???
                    # We are done so just break out of the thing...
                    self.advance()
                    break
            elif self.peek().value == ",": # Layouts that do not require a value... (for example "std140" and others...)
                # Just consume the comma and generate the DeclaratorLayout object...
                obj = DeclaratorLayout(name)
                decls.append(obj)
                self.advance() # Eat the comma such that we are on the next (potential) qualifier
            elif self.peek().value == ")": # End of the thing???
                obj = DeclaratorLayout(name)
                decls.append(obj)
                self.advance()
                break
        # Show where we breaked...
        # print("self.peek(): "+str(self.peek().kind)+", "+str(self.peek().value))
        # Now we assume that all the qualifiers are in the list "decls" . Create the actual layout object...
        layout_object = LayoutQualifier(decls)
        return layout_object

    def parse_translation_unit(self) -> TranslationUnit:
        items: List[TopLevel] = []
        while self.peek().kind != "EOF":
            t = self.peek()
            # print("t.value: "+str(t.value))
            # print("t.kind: "+str(t.kind))
            # if t.kind == "KW" and t.value == "struct":

            # Try to parse layouts first...
            if t.value == "layout" and t.kind == "KW": # layout?
                items.append(self.parse_layout())
                continue

            if self._looks_like_struct_decl_stmt():
                items.append(self.parse_struct_toplevel_decl())
                continue

            if t.value in ("uniform", "in", "out", "buffer") and self._looks_like_interface_block():
                items.append(self.parse_interface_block())
                continue

            if self._looks_like_decl():
                '''
                save = self.i
                _ = self.parse_type_name()
                _ = self.expect("ID")
                if self.peek().kind == "(":
                    self.i = save
                    # print("Function definition...")
                    items.append(self.parse_function_def_or_decl())
                else:
                    # print("Function definition...")
                    self.i = save
                    items.append(self.parse_global_decl())
                '''

                save = self.i

                # Parse return type
                _ = self.parse_type_name()

                # skip array dimensions on return type
                while self.match("["):
                    if not self.match("]"):
                        self.parse_expr(0)
                        self.expect("]")

                # Now expect function / variable name
                _ = self.expect("ID")

                if self.peek().kind == "(":
                    self.i = save
                    items.append(self.parse_function_def_or_decl())
                else:
                    self.i = save
                    items.append(self.parse_global_decl())

                continue
            # print("Ignoring this stuff here: "+str(self.peek().kind)+" , "+str(self.peek().value))
            self.advance()

        return TranslationUnit(items)

'''
def parse_to_tree(shader_source: str) -> TranslationUnit:
    if DEBUG:
        global current_input
        current_input = shader_source
    tokens = lex(shader_source)
    p = Parser(tokens)
    return p.parse_translation_unit()
'''


def parse_directive(line: str):
    parts = line.split()
    if parts[0] == "#version":
        # return VersionDirective(parts[1]) # Doesn't work for example "#version 300 es" has two string parts after the "#version" token...
        return VersionDirective(" ".join(parts[1:]))
    if parts[0] == "#extension":
        # "#extension GL_EXT_YUV_target : require"
        name = parts[1]
        behavior = parts[-1]
        return ExtensionDirective(name, behavior)
    if parts[0] == "#pragma": # Pragma directives too...
        pragma_string = " ".join(parts[1:])
        return PragmaDirective(pragma_string)
    return None

# This here also supports the directives...
def parse_to_tree(shader_source: str) -> TranslationUnit:
    if DEBUG:
        global current_input
        current_input = shader_source

    lines = shader_source.splitlines()
    directives = []
    body_lines = []

    for line in lines:
        s = line.strip()
        if s.startswith("#version"):
            directives.append(("version", s))
        elif s.startswith("#extension"):
            directives.append(("extension", s))
        elif s.startswith("#pragma"):
            directives.append(("pragma", s))
        else:
            body_lines.append(line)

    tokens = lex("\n".join(body_lines))
    p = Parser(tokens, original_input=shader_source)
    # print("tokens: "+str(tokens))
    tu = p.parse_translation_unit()

    # tu.directives = directives
    tu.directives = [parse_directive(s) for _, s in directives]

    return tu
here:
# shader_unparser.py
from __future__ import annotations

from shader_ast import *
from const import *

# -----------------------------
# Small helpers
# -----------------------------

def _is_dim_list(x) -> bool:
    return isinstance(x, list)

def _flatten_members(members):
    """
    Accepts:
      - List[StructField]
      - List[List[StructField]]
      - mixed (because fuzzing 😈)

    Returns:
      - flat List[StructField]
    """
    out = []
    for m in members:
        if isinstance(m, list):
            out.extend(m)
        else:
            out.append(m)
    return out

def flatten_commas(e: Expr) -> list[Expr]:
    if isinstance(e, BinaryExpr) and e.op == ",":
        return flatten_commas(e.left) + flatten_commas(e.right)
    return [e]

def unparse_expr(e: Expr) -> str:
    if isinstance(e, Identifier):
        return e.name
    if isinstance(e, IntLiteral):
        return str(e.value)
    if isinstance(e, FloatLiteral):
        # keep stable-ish textual form
        return repr(e.value)
    if isinstance(e, BoolLiteral):
        return "true" if e.value else "false"
    if isinstance(e, UnaryExpr):
        if e.postfix:
            return f"{unparse_expr(e.operand)}{e.op}"
        return f"{e.op}{unparse_expr(e.operand)}"
    if isinstance(e, BinaryExpr):
        # print("e.left: "+str(e.left))
        # print("e.right: "+str(e.right))
        # if e.op == "," or e.op == "=": # Check for the comma "operator" which is actually used to separate function arguments and such... Also do not wrap when assigning variables etc etc...
        if e.op == "=" or e.op == ",":
            return f"{unparse_expr(e.left)} {e.op} {unparse_expr(e.right)}"
        return f"({unparse_expr(e.left)} {e.op} {unparse_expr(e.right)})"
    if isinstance(e, TernaryExpr):
        return f"({unparse_expr(e.cond)} ? {unparse_expr(e.then_expr)} : {unparse_expr(e.else_expr)})"
    if isinstance(e, CallExpr):
        # args = ", ".join(unparse_expr(a) for a in e.args)

        flat_args = []
        for a in e.args:
            flat_args.extend(flatten_commas(a))
        args = ", ".join(unparse_expr(a) for a in flat_args)

        return f"{unparse_expr(e.callee)}({args})" # This originally had the paranthesis around it, but because we actually break the call convention, because we get function calls like "pow((1, 2))" instead of "pow(1, 2)"
    if isinstance(e, IndexExpr):
        return f"{unparse_expr(e.base)}[{unparse_expr(e.index)}]"
    if isinstance(e, MemberExpr):
        return f"{unparse_expr(e.base)}.{e.member}"
    raise TypeError(f"Unhandled expr: {type(e)}")


def unparse_type(t: TypeName) -> str:
    parts = []
    if getattr(t, "qualifiers", None):
        parts.extend(t.qualifiers)
    if getattr(t, "precision", None):
        parts.append(t.precision)
    parts.append(t.name)
    # Now check for array_dims (array_dims: List[Optional[Expr]] = None)
    arr = ""
    # unparse_array_suffix(getattr(p, "array_dims", None)
    if getattr(t, "array_dims", None):
        arr += unparse_array_suffix(t.array_dims) # Unparse that shit...
    # print("ar: "+str(arr))
    return " ".join(parts) + arr


def unparse_array_suffix(dims) -> str:
    """
    Accepts:
      - None
      - Expr (single dimension)
      - list[Optional[Expr]] (multi-dim; None => unsized [])
    Returns: "", "[..]", "[..][..]" etc.
    """
    if dims is None:
        return ""

    # single-dim legacy: Expr
    if isinstance(dims, Expr):
        return f"[{unparse_expr(dims)}]"

    # multi-dim: list
    if _is_dim_list(dims):
        out = ""
        for d in dims:
            if d is None:
                out += "[]"
            else:
                out += f"[{unparse_expr(d)}]"
        return out

    # sometimes you accidentally store a tuple; handle it too
    if isinstance(dims, tuple):
        out = ""
        for d in dims:
            if d is None:
                out += "[]"
            else:
                out += f"[{unparse_expr(d)}]"
        return out

    raise TypeError(f"Unhandled array dims type: {type(dims)}")


# -----------------------------
# Struct specifier + body
# -----------------------------

def _unparse_struct_body(struct_type: StructType) -> str:
    out = "{\n"

    members = _flatten_members(struct_type.members)

    for m in members:
        line = f"  {unparse_type(m.type_name)} {m.name}"

        dims = getattr(m, "array_dims", None)
        if dims is None:
            dims = getattr(m, "array_size", None)

        line += unparse_array_suffix(dims)
        out += line + ";\n"

    out += "}"
    return out


def unparse_struct_specifier(struct_type: StructType) -> str:
    name = struct_type.name if struct_type.name else ""
    if name:
        return f"struct {name} {_unparse_struct_body(struct_type)}"
    return f"struct {_unparse_struct_body(struct_type)}"

# -----------------------------
# Statements
# -----------------------------

def unparse_stmt(s: Stmt, indent: int = 0) -> str:
    pad = "  " * indent

    if isinstance(s, EmptyStmt):
        return pad + ";\n"

    if isinstance(s, ExprStmt):
        return pad + f"{unparse_expr(s.expr)};\n"

    if isinstance(s, DeclStmt):
        if not s.decls:
            return pad + ";\n"

        # all decls share same type_name by construction in your parser
        t = s.decls[0].type_name
        parts = []
        for d in s.decls:
            frag = d.name

            # multi-dim arrays
            frag += unparse_array_suffix(d.array_dims)

            if d.init is not None:
                frag += f" = {unparse_expr(d.init)}"
            parts.append(frag)

        return pad + f"{unparse_type(t)} " + ", ".join(parts) + ";\n"

    if isinstance(s, BlockStmt):
        out = pad + "{\n"
        for st in s.stmts:
            out += unparse_stmt(st, indent + 1)
        out += pad + "}\n"
        return out

    if isinstance(s, IfStmt):
        out = pad + f"if ({unparse_expr(s.cond)})\n"
        out += unparse_stmt(s.then_branch, indent + (0 if isinstance(s.then_branch, BlockStmt) else 1))
        if s.else_branch is not None:
            out += pad + "else\n"
            out += unparse_stmt(s.else_branch, indent + (0 if isinstance(s.else_branch, BlockStmt) else 1))
        return out

    if isinstance(s, WhileStmt):
        out = pad + f"while ({unparse_expr(s.cond)})\n"
        out += unparse_stmt(s.body, indent)
        return out

    if isinstance(s, DoWhileStmt):
        out = pad + "do\n"
        out += unparse_stmt(s.body, indent)
        out += pad + f"while ({unparse_expr(s.cond)});\n"
        return out

    if isinstance(s, ForStmt):
        def _uinit(x):
            if x is None:
                return ""
            txt = unparse_stmt(x, 0).strip()
            return txt[:-1] if txt.endswith(";") else txt

        init = _uinit(s.init)
        cond = unparse_expr(s.cond) if s.cond else ""
        loop = unparse_expr(s.loop) if s.loop else ""
        out = pad + f"for ({init}; {cond}; {loop})\n"
        out += unparse_stmt(s.body, indent)
        return out

    if isinstance(s, ReturnStmt):
        if s.expr is None:
            return pad + "return;\n"
        return pad + f"return {unparse_expr(s.expr)};\n"

    if isinstance(s, BreakStmt):
        return pad + "break;\n"

    if isinstance(s, ContinueStmt):
        return pad + "continue;\n"

    if isinstance(s, DiscardStmt):
        return pad + "discard;\n"

    # ---- Switch support (your custom classes) ----
    if isinstance(s, SwitchStmt):
        out = pad + f"switch ({unparse_expr(s.expr)})\n"
        out += unparse_stmt(s.body, indent)
        return out

    if isinstance(s, CaseStmt):
        out = pad + f"case {unparse_expr(s.expr)}:\n"
        for st in s.stmts:
            out += unparse_stmt(st, indent + 1)
        return out

    if isinstance(s, DefaultStmt):
        out = pad + "default:\n"
        for st in s.stmts:
            out += unparse_stmt(st, indent + 1)
        return out

    # This is to handle inline struct definitions inside functions...
    if isinstance(s, StructDecl):
        # assert False
        storage = None
        if s.declarators and getattr(s.declarators[0], "storage", None):
            storage = s.declarators[0].storage

        out = ""
        if storage:
            out += storage + " "

        out += unparse_struct_specifier(s.struct_type) # Originally was +=
        if s.declarators:
            out += " " + ", ".join(_unparse_declarator(d) for d in s.declarators)
        out += ";\n\n"
        # continue
        return out

    raise TypeError(f"Unhandled stmt: {type(s)}")


# -----------------------------
# Top-level
# -----------------------------

def _unparse_declarator(d: Declarator) -> str:
    s = d.name
    s += unparse_array_suffix(getattr(d, "array_dims", None) or getattr(d, "array_size", None))
    if getattr(d, "init", None) is not None:
        s += f" = {unparse_expr(d.init)}"
    return s


def _unparse_var_decl(d: VarDecl) -> str:
    s = d.name + unparse_array_suffix(d.array_dims)
    if d.init is not None:
        s += f" = {unparse_expr(d.init)}"
    return s


def unparse_tu(tu: TranslationUnit) -> str:
    out = ""
    # Process directives first
    for d in getattr(tu, "directives", []):
        if isinstance(d, PragmaDirective):
            out += f"#pragma {d.pragma_string}"
        elif isinstance(d, VersionDirective):
            out += f"#version {d.version}\n"
        elif isinstance(d, ExtensionDirective):
            # print("d.name: "+str(d.name))
            if ":" in d.name: # Check for potential errors here. This is a parsing artifact due to the way we process these...
                d.name = d.name.replace(":", "")
            out += f"#extension {d.name} : {d.behavior}\n"
    if out:
        out += "\n"

        # Check for the mandatory precision statements. If these do not exist, then the shader gets rejected right out the gate...

    if "precision mediump float" not in out and "highp" not in out: # Check for the high precision floats, if they do exist, then do not emit the mediump preamble thing...

        prec_preamble = '''precision mediump float;\nprecision mediump int;\n\n'''
        out += prec_preamble #  + out # Prepend that...

    # print("tu.items: "+str(tu.items))

    for item in tu.items:
        # old explicit struct definition form (if you still use it)
        # print("item: "+str(item))
        if isinstance(item, StructDef):
            out += f"struct {item.name} {{\n"
            for f in item.fields:
                line = f"  {unparse_type(f.type_name)} {f.name}"
                # StructField may carry list dims in array_size too
                dims = getattr(f, "array_dims", None)
                if dims is None:
                    dims = getattr(f, "array_size", None)
                line += unparse_array_suffix(dims)
                out += line + ";\n"
            out += "};\n\n"
            continue

        # struct specifier + declarators (your common case)
        if isinstance(item, StructDecl):
            # assert False
            qualifiers = []
            if item.declarators:
                qualifiers = item.declarators[0].qualifiers

            interp = [q for q in qualifiers if q in INTERP_QUALIFIERS]
            storage = [q for q in qualifiers if q in STORAGE_QUALIFIERS]
            precision = [q for q in qualifiers if q in PRECISION_QUALIFIERS]

            if interp or storage or precision:
                out += " ".join(interp + storage + precision) + " "

            out += unparse_struct_specifier(item.struct_type)

            if item.declarators:
                out += " " + ", ".join(_unparse_declarator(d) for d in item.declarators)

            out += ";\n\n"
            continue

        # generic "Declaration" used by your parser for struct-specifier declarations too
        if isinstance(item, Declaration):
            # if it's a struct specifier:
            if isinstance(item.type, StructType):
                out += unparse_struct_specifier(item.type)
                if item.declarators:
                    out += " " + ", ".join(_unparse_declarator(d) for d in item.declarators)
                out += ";\n\n"
            else:
                # fallback: try like a normal decl statement
                # (you can extend this later)
                out += ";\n\n"
            continue

        if isinstance(item, InterfaceBlock):
            # storage is like: uniform/in/out/buffer
            out += f"{item.storage} {item.name} "
            # members should be list[StructField]-like
            tmp_struct = StructType(name=None, members=item.members)
            out += _unparse_struct_body(tmp_struct)
            if item.instance:
                out += f" {item.instance}"
                # Add possible array lengths...
                out += unparse_array_suffix(item.array_dims)
            out += ";\n\n"
            continue

        if isinstance(item, FunctionDef):
            # print("function definition item: "+str(item))
            params = []
            for p in item.params:
                ps = f"{unparse_type(p.type_name)} {p.name}"
                ps += unparse_array_suffix(getattr(p, "array_dims", None) or getattr(p, "array_size", None))
                params.append(ps)
            # NEW: Unparse the return type array types
            # array_return = ""

            out += f"{unparse_type(item.return_type)} {item.name}(" + ", ".join(params) + ")\n"
            out += unparse_stmt(item.body, 0)
            out += "\n"
            continue

        if isinstance(item, FunctionDecl):
            # print("function declaration item: "+str(item))
            params = []
            for p in item.params:
                ps = f"{unparse_type(p.type_name)} {p.name}"
                ps += unparse_array_suffix(getattr(p, "array_dims", None) or getattr(p, "array_size", None))
                params.append(ps)
            out += f"{unparse_type(item.return_type)} {item.name}(" + ", ".join(params) + ");\n"
            # out += unparse_stmt(item.body, 0)
            # out += "\n"
            continue

        if isinstance(item, GlobalDecl):
            # group as single declaration statement
            out += unparse_stmt(DeclStmt(item.decls), 0)
            out += "\n"
            continue

        # Layout object?

        if isinstance(item, LayoutQualifier):
            the_string = "layout("
            # print("item.declarators: "+str(item.declarators))
            for o in item.declarators:
                s = str(o.name)
                if o.value != None:
                    s += "="+str(o.value)
                s += ", " # Add the comma...
                the_string += s
            the_string = the_string[:-2] # Cut off the excess ", "
            the_string += ") " # close
            out += the_string
            # Now actually do NOT append the newline since layouts must be on the same line I think...
            continue
        # unknown => ignore safely
        out += "\n"

    return out
and here:
# shader_lexer.py
from __future__ import annotations

from const import *

from dataclasses import dataclass
from typing import List, Optional
import re

# Regex building
_OP_RE = "|".join(re.escape(op) for op in OPERATORS)
_PUNCT_RE = "|".join(re.escape(p) for p in sorted(PUNCT, key=len, reverse=True))


# Here the float shit originally was  (?P<FLOAT>(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?[fFlL]?) |

# (?P<FLOAT>(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?(?:lf|LF|f|F|l|L)?) |

TOKEN_RE = re.compile(
    rf"""
    (?P<WS>\s+) |
    (?P<LINECOMMENT>//[^\n]*\n?) |
    (?P<BLOCKCOMMENT>/\*.*?\*/) |
    (?P<FLOAT>(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?(?:lf|LF|f|F|l|L)?) |
    (?P<INT>
        0[xX][0-9a-fA-F]+[uU]? |   # hex
        0[0-7]+[uU]? |            # octal
        \d+[uU]?                  # decimal
    ) |
    (?P<ID>[A-Za-z_][A-Za-z0-9_]*) |
    (?P<OP>{_OP_RE}) |
    (?P<PUNCT>{_PUNCT_RE})
    """,
    re.VERBOSE | re.DOTALL | re.MULTILINE,
)


@dataclass
class Token:
    kind: str
    value: str
    pos: int


def lex(src: str) -> List[Token]:
    out: List[Token] = []
    i = 0
    for m in TOKEN_RE.finditer(src):
        kind = m.lastgroup
        value = m.group(kind)
        pos = m.start()

        if kind in ("WS", "LINECOMMENT", "BLOCKCOMMENT"):
            continue

        if kind == "ID" and value in KEYWORDS:
            out.append(Token("KW", value, pos))
        elif kind == "PUNCT":
            out.append(Token(value, value, pos))  # punctuation as its own kind
        elif kind == "OP":
            out.append(Token("OP", value, pos))
        elif kind == "INT":
            out.append(Token("INT", value, pos))
        elif kind == "FLOAT":
            out.append(Token("FLOAT", value, pos))
        else:
            out.append(Token(kind, value, pos))

        i = m.end()

    out.append(Token("EOF", "", len(src)))
    return out
can you make a similar shader custom mutator for this input format we have (aka header + the hlsl source code?) I want it to have the lexer, parser, unparser (back to the input format from the mutated structure) and the actual mutator.. Also can you please tell me a test file in python that for example does round trip parsing tests with the fuzzer binary? (see if errors, then parse and unparse and then see if errors. if different, then failure.)
```




