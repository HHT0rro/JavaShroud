use super::page::{PageError, PageKind, PageRequest};
use jsrt_shell::SupportedTarget;
use std::fmt;

/// The VM boundary accepts only an authenticated page-shaped request. Java
/// object conversion and method dispatch remain outside this safe crate; an
/// unavailable route is an explicit error rather than a fallback interpreter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmBoundary {
    target: SupportedTarget,
}

impl VmBoundary {
    pub const fn new(target: SupportedTarget) -> Self {
        Self { target }
    }

    pub const fn target(&self) -> SupportedTarget {
        self.target
    }

    pub fn validate_request(&self, request: &PageRequest) -> Result<(), VmError> {
        if request.kind() != PageKind::Vm {
            return Err(VmError::WrongPageKind {
                expected: PageKind::Vm,
                actual: request.kind(),
            });
        }
        Ok(())
    }

    /// Keep the route explicit and fail closed until a page program has been
    /// authenticated and attached by the owning runtime planner.
    pub fn execute(&self, request: &PageRequest) -> Result<VmResult, VmError> {
        self.validate_request(request)?;
        Err(VmError::RouteUnavailable {
            target: self.target,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmResult {
    Void,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmError {
    InvalidPage(PageError),
    WrongPageKind {
        expected: PageKind,
        actual: PageKind,
    },
    RouteUnavailable {
        target: SupportedTarget,
    },
}

impl fmt::Display for VmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPage(error) => error.fmt(formatter),
            Self::WrongPageKind { expected, actual } => {
                write!(
                    formatter,
                    "VM page kind mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::RouteUnavailable { target } => {
                write!(
                    formatter,
                    "VM page route is unavailable for {}",
                    target.triple()
                )
            }
        }
    }
}

impl std::error::Error for VmError {}

impl From<PageError> for VmError {
    fn from(error: PageError) -> Self {
        Self::InvalidPage(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::PAGE_HANDLE_SIZE;

    #[test]
    fn vm_boundary_rejects_non_vm_pages_and_never_falls_back() {
        let boundary = VmBoundary::new(SupportedTarget::WindowsX64Gnu);
        let class_page =
            PageRequest::new(&[1; PAGE_HANDLE_SIZE], 0, &[2], PageKind::Class).expect("page");
        assert!(matches!(
            boundary.validate_request(&class_page),
            Err(VmError::WrongPageKind { .. })
        ));
        let vm_page =
            PageRequest::new(&[1; PAGE_HANDLE_SIZE], 0, &[2], PageKind::Vm).expect("page");
        assert_eq!(
            boundary.execute(&vm_page),
            Err(VmError::RouteUnavailable {
                target: SupportedTarget::WindowsX64Gnu
            })
        );
    }
}
