/**
 Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>
 **/

//Missing Stuff in @types/frida-gum

declare namespace Interceptor {
    /**
     * Ensure any pending changes have been committed to memory.
     *
     * This is should only be done in the few cases where this is necessary,
     * e.g. if you just attach()ed to or replace()d a function that you are about
     * to call using NativeFunction. Pending changes are flushed automatically
     * whenever the current thread is about to leave the JavaScript runtime or calls send().
     * This includes any API built on top of send(), like when returning from an RPC method,
     * and calling any method on the console API.
     */
    function flush(): void;
}