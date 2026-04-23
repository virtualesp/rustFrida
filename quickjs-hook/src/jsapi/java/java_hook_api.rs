//! JS API: Java.hook / Java.unhook
//!
//! 安装、卸载与安装期资源回滚拆分到子模块，降低单文件复杂度。

mod install;
mod install_support;
pub(crate) mod lua_install;
mod uninstall;

pub(super) use install::js_java_hook;
pub(super) use lua_install::js_lua_hook;
pub(super) use uninstall::js_java_unhook;
