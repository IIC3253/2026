import random

import pytest

# Autouse fixture para fijar la aleatoriedad y garantizar condiciones iguales
# de correccion para todas las runs
BASE_SEED = 20260705
REPS = 3

@pytest.fixture(autouse=True)
def _seed_rng():
    random.seed(BASE_SEED)
    yield

TEST_TIMEOUT = 5  # seconds
import pytest_timeout
pytestmark = pytest.mark.timeout(TEST_TIMEOUT)


def _reseed(rep):
    random.seed(BASE_SEED + 1 + rep)


# Importamos las clases con gettattr para evitar crash si alguna no está
# implementada
import student_pregunta2 as _student

StudentParticipant = getattr(_student, "TraceableRingSignatureParticipant", None)
StudentVerifier = getattr(_student, "Verifier", None)

from reference_pregunta2 import TraceableRingSignatureParticipant as RefParticipant
from reference_pregunta2 import Verifier as RefVerifier


def _require(obj, name):
    if obj is None:
        pytest.fail(f"{name} no está implementada en pregunta2.py", pytrace=False)
    return obj

# g=4 genera el subgrupo de orden q=107.
# Generadores malos (|<g>| != q): 2 (orden 642), 1 (orden 1), 642 (orden 2).
# Módulos/órdenes compuestos para los tests de primalidad: 649=11*59, 106=2*53,
# más la unidad 1 y la potencia perfecta 9=3^2 (que un test Solovay-Strassen
# debe rechazar por su chequeo de potencia perfecta).
SMALL_G, SMALL_Q, SMALL_P = 4, 107, 643
G_WRONG_ORDER = [2, 1, 642]
P_NOT_PRIME = [649, 1, 9]
Q_NOT_PRIME = [106, 1, 9]


BIG_Q = 63762351364972653564641699529205510489263266834182771617563631363277932854227
BIG_P = 3443166973708523292490651774577097566420216409045869667348436093617008374128259
BIG_G = 2016442040760482059049717278161383257391833415528589803024442481790083910610761

# Helpers de firma/verificación

def _sign(participant, public_keys, tag, message):
    return participant.generate_traceable_ring_signature(public_keys, tag, message)


def _verify(verifier, public_keys, message, tag, sig):
    return verifier.verify_signature(public_keys, message, tag, sig)


def _build_ring(ParticipantCls, g, q, p, n):
    ring = [ParticipantCls(g, q, p) for _ in range(n)]
    public_keys = [x.get_public_key() for x in ring]
    return ring, public_keys


def _unpack_sig(sig, n):
    """Valida la forma de la firma ([s1..sn], c1, f) y devuelve sus partes, con
    un mensaje de error claro en vez de un error opaco de desempaquetado."""
    try:
        signatures, c, f = sig
    except (TypeError, ValueError):
        pytest.fail(f"la firma no tiene la forma ([s1..sn], c1, f): {sig!r}", pytrace=False)
    if not isinstance(signatures, (list, tuple)) or len(signatures) != n:
        pytest.fail(f"la lista de firmas debe tener largo {n}: {signatures!r}", pytrace=False)
    return signatures, c, f


def _pos_index(pos, n):
    return {"first": 0, "middle": n // 2, "last": n - 1}[pos]


# [0.25 puntos] Al inicializar un TraceableRingSignatureParticipant con un valor
# de p que no es primo, se debe obtener una excepción.
# Casos borde: compuesto impar, 1, cuadrado perfecto

@pytest.mark.parametrize("p", P_NOT_PRIME)
def test_init_p_not_prime(p):
    Participant = _require(StudentParticipant, "TraceableRingSignatureParticipant")
    with pytest.raises(Exception):
        Participant(SMALL_G, SMALL_Q, p)


# [0.25 puntos] Al inicializar un TraceableRingSignatureParticipant con un
# valor de p primo y un valor de q que no es primo, se debe obtener una
# excepción. 

@pytest.mark.parametrize("q", Q_NOT_PRIME)
def test_init_q_not_prime(q):
    Participant = _require(StudentParticipant, "TraceableRingSignatureParticipant")
    with pytest.raises(Exception):
        Participant(SMALL_G, q, SMALL_P)


# [0.25 puntos] Al inicializar un TraceableRingSignatureParticipant con valores
# primos de p y q, y con un elemento g \in Z_p^* tal que |⟨g⟩| != q, se debe
# obtener una excepción. 

@pytest.mark.parametrize("g", G_WRONG_ORDER)
def test_init_g_wrong_order(g):
    Participant = _require(StudentParticipant, "TraceableRingSignatureParticipant")
    with pytest.raises(Exception):
        Participant(g, SMALL_Q, SMALL_P)


# [0.25 puntos] Al inicializar un Verifier con valores primos de p y q, y con un
# elemento g \in Z_p^* tal que |⟨g⟩| != q, se debe obtener una excepción.

@pytest.mark.parametrize("g", G_WRONG_ORDER)
def test_verifier_g_wrong_order(g):
    Verifier = _require(StudentVerifier, "Verifier")
    with pytest.raises(Exception):
        Verifier(g, SMALL_Q, SMALL_P)


# [0.5 puntos] Para un conjunto válido de l participantes inicializados con los
# mismos parámetros p, q y g, si uno de ellos genera una firma para una lista de
# claves públicas public_keys, un tag tag y un mensaje message, entonces la
# firma debe tener la forma ([s_1, ..., s_l], c_1, f) y el método verify
# signature con estos parámetros debe retornar (True, True)
# Casos borde: anillo minimal (n=2), firmante posicionado al principio/al medio/
# al final del anillo.

_VALID_CASES = (
    [("student_student", n, pos) for n in (2, 3, 5) for pos in ("first", "middle", "last")]
    + [("student_ref", n, "first") for n in (2, 3, 5)]
    + [("ref_student", n, "first") for n in (2, 3, 5)]
)


@pytest.mark.parametrize("rep", range(REPS))
@pytest.mark.parametrize("mode,n,pos", _VALID_CASES)
def test_valid_signature(mode, n, pos, rep):
    _reseed(rep)
    tag = "Encuesta IIC3253"
    message = "Hello from IIC3253"

    if mode == "student_student":
        Participant = _require(StudentParticipant, "TraceableRingSignatureParticipant")
        Verifier = _require(StudentVerifier, "Verifier")
        ring, pks = _build_ring(Participant, BIG_G, BIG_Q, BIG_P, n)
        sig = _sign(ring[_pos_index(pos, n)], pks, tag, message)
        _unpack_sig(sig, n)  # valida la forma ([s1..sn], c1, f) exigida por la rúbrica
        result = _verify(Verifier(BIG_G, BIG_Q, BIG_P), pks, message, tag, sig)
        assert tuple(result) == (True, True)

    elif mode == "student_ref":
        # El verifier de referencia debe aceptar una firma del estudiante.
        Participant = _require(StudentParticipant, "TraceableRingSignatureParticipant")
        ring, pks = _build_ring(Participant, BIG_G, BIG_Q, BIG_P, n)
        sig = _sign(ring[0], pks, tag, message)
        result = _verify(RefVerifier(BIG_G, BIG_Q, BIG_P), pks, message, tag, sig)
        assert result[0] is True

    else:  # ref_student
        # El verifier del estudiante debe aceptar una firma de referencia.
        #
        # El enunciado fija str(n) y la convención de hash-al-GRUPO (% p) pero NO
        # si el challenge escalar, y por ende c1, se reduce mod q. Eso deja
        # dos bandos auto-consistentes que NO interoperan con una sola convención
        # de c1:
        #   * verifiers c1-reducido (reducen c internamente, comparan c1 tal cual)
        #   * verifiers c1-plano (nunca reducen, comparan crudo).
        # Ningún c1 de referencia fijo satisface a ambos, así que aceptamos al
        # verifier del estudiante si valida O una firma de referencia reducida O
        # una sin reducir (ambas válidas). Un verifier totalmente correcto (reduce
        # ambos lados) acepta las dos; cada bando acepta la suya; solo un verifier
        # genuinamente roto - serialización / hashing / matemática mala - no
        # acepta ninguna.
        Verifier = _require(StudentVerifier, "Verifier")
        ring, pks = _build_ring(RefParticipant, BIG_G, BIG_Q, BIG_P, n)
        signer = ring[0]
        accepted = False
        for red in (True, False):
            signer.reduce_challenge = red
            sig = _sign(signer, pks, tag, message)
            if _verify(Verifier(BIG_G, BIG_Q, BIG_P), pks, message, tag, sig)[0] is True:
                accepted = True
                break
        assert accepted


# [0.25 puntos] Para un conjunto válido de l participantes inicializados con los
#  mismos parámetros p, q y g, si un mismo participante genera dos firmas
# válidas para mensajes distintos usando la misma lista de claves públicas
# public_keys y el mismo tag tag, entonces el verificador debe retornar
# (True, True) al verificar la primera firma y (True, False) al verificar la
# segunda firma.
# Casos borde: anillo minimal (n=2), firmante en primera/última posición.

_LINK_CASES = (
    [("same", n, pos) for n in (2, 3, 5) for pos in ("first", "last")]
    + [("distinct", n, "first") for n in (2, 3, 5)]
)


@pytest.mark.parametrize("rep", range(REPS))
@pytest.mark.parametrize("kind,n,pos", _LINK_CASES)
def test_linkability(kind, n, pos, rep):
    _reseed(rep)
    Participant = _require(StudentParticipant, "TraceableRingSignatureParticipant")
    Verifier = _require(StudentVerifier, "Verifier")
    tag = "Encuesta IIC3253"
    ring, pks = _build_ring(Participant, BIG_G, BIG_Q, BIG_P, n)
    verifier = Verifier(BIG_G, BIG_Q, BIG_P)

    if kind == "same":
        signer = ring[_pos_index(pos, n)]
        sig1 = _sign(signer, pks, tag, "message one")
        assert tuple(_verify(verifier, pks, "message one", tag, sig1)) == (True, True)
        sig2 = _sign(signer, pks, tag, "message two")
        assert tuple(_verify(verifier, pks, "message two", tag, sig2)) == (True, False)
    else:
        sig_a = _sign(ring[0], pks, tag, "from A")
        assert tuple(_verify(verifier, pks, "from A", tag, sig_a)) == (True, True)
        sig_b = _sign(ring[1], pks, tag, "from B")
        assert tuple(_verify(verifier, pks, "from B", tag, sig_b)) == (True, True)


# [0.25 puntos] Para una frima válida \sigma = ([s_1, ..., s_l], c_1, f), si se
# define una firma \sigma' = ([s'_1, s_2, ..., s_l], c_1, f) con s'_1 != s_1,
# entonces verify signature(public keys, message, tag, σ') debe rechazar la
# firma.
# Casos borde: anillo minimal (n=2), perturbación minimalmente detectable
# s'_1 = s_1 + 1.

@pytest.mark.parametrize("rep", range(REPS))
@pytest.mark.parametrize("n", [2, 3, 5])
def test_tampered_signature(n, rep):
    _reseed(rep)
    Participant = _require(StudentParticipant, "TraceableRingSignatureParticipant")
    Verifier = _require(StudentVerifier, "Verifier")
    tag = "Encuesta IIC3253"
    message = "Hello from IIC3253"
    ring, pks = _build_ring(Participant, BIG_G, BIG_Q, BIG_P, n)
    signatures, c, f = _unpack_sig(_sign(ring[0], pks, tag, message), n)

    tampered = list(signatures)
    tampered[0] = (tampered[0] + 1) % BIG_Q

    verifier = Verifier(BIG_G, BIG_Q, BIG_P)
    result = _verify(verifier, pks, message, tag, (tampered, c, f))
    assert result[0] is False
