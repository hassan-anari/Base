import { reactive } from 'vue'

export const toasts = reactive([])
let seq = 0

export function toast(message, type = 'info', ttl = 3200) {
  const id = ++seq
  toasts.push({ id, message, type })
  setTimeout(() => {
    const i = toasts.findIndex((t) => t.id === id)
    if (i !== -1) toasts.splice(i, 1)
  }, ttl)
}