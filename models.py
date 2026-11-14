"""
Modelos de datos del experimento REDES.

Estructuras utilizadas para representar
los resultados de verificacion.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class VerificationResult:
    case_id: str
    patch_applied: bool
    functional_rc: Optional[int]
    security_rc: Optional[int]

    def __post_init__(self):
        if type(self.patch_applied) is not bool:
            raise ValueError("patch_applied debe ser booleano")

        for name in ("functional_rc", "security_rc"):
            value = getattr(self, name)
            if value is not None and type(value) is not int:
                raise ValueError(f"{name} debe ser entero o None")

        if not self.patch_applied and (
            self.functional_rc is not None
            or self.security_rc is not None
        ):
            raise ValueError(
                "No puede haber pruebas ejecutadas "
                "si el parche no se aplico"
            )

    @property
    def functional_test_executed(self):
        return self.functional_rc is not None

    @property
    def security_test_executed(self):
        return self.security_rc is not None

    @property
    def A(self):
        return int(self.patch_applied)

    @property
    def F(self):
        return int(
            self.patch_applied and self.functional_rc == 0
        )

    @property
    def S(self):
        return int(
            self.patch_applied and self.security_rc == 0
        )

    @property
    def verified_repair(self):
        return self.A * self.F * self.S
