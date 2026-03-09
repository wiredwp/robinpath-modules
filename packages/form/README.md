# @robinpath/form

> Declarative form builder — define fields inline in RobinPath scripts to generate form schemas, validate submissions, and embed forms anywhere

![Category](https://img.shields.io/badge/category-Web-blue) ![Functions](https://img.shields.io/badge/functions-27-green) ![Auth](https://img.shields.io/badge/auth-none-lightgrey) ![License](https://img.shields.io/badge/license-MIT-brightgreen)

## Why use this module?

The `form` module lets you:

- Generate embeddable forms
- Build multi-step wizards

All functions are callable directly from RobinPath scripts with a simple, consistent API.

## Installation

```bash
npm install @robinpath/form
```

## Quick Start

No credentials needed — start using it right away:

```robinpath
form.textarea "bio" {"label": "Bio", "maxLength": 1000}
```

## Available Functions

| Function | Description |
|----------|-------------|
| `form.text` | Declare a text input field |
| `form.textarea` | Declare a multi-line text field |
| `form.number` | Declare a number input field |
| `form.email` | Declare an email input field |
| `form.url` | Declare a URL input field |
| `form.phone` | Declare a phone number input field |
| `form.password` | Declare a password input field |
| `form.select` | Declare a single-select dropdown |
| `form.multiselect` | Declare a multi-select field |
| `form.checkbox` | Declare a checkbox field |
| `form.radio` | Declare a radio button group |
| `form.date` | Declare a date input field |
| `form.time` | Declare a time input field |
| `form.datetime` | Declare a date-time input field |
| `form.file` | Declare a file upload field |
| `form.hidden` | Declare a hidden field |
| `form.color` | Declare a color picker field |
| `form.range` | Declare a range slider field |
| `form.json` | Declare a JSON input field |
| `form.config` | Set form-level configuration (title, submitLabel, etc.) |
| `form.getForm` | Get the complete form schema |
| `form.validate` | Validate data against declared fields |
| `form.setData` | Inject submitted form data |
| `form.reset` | Clear all fields, config, and data |
| `form.group` | Define a visual field group |
| `form.step` | Define a multi-step wizard step |
| `form.toEmbed` | Generate embed code (iframe, script, web component) |

## Examples

### Declare a multi-line text field.

```robinpath
form.textarea "bio" {"label": "Bio", "maxLength": 1000}
```

### Declare a number input field.

```robinpath
form.number "age" {"label": "Age", "min": 0, "max": 120}
```

### Declare an email input field with automatic email format validation.

```robinpath
form.email "email" {"label": "Email", "required": true}
```

## Integration with RobinPath

```typescript
import { RobinPath } from "@wiredwp/robinpath";
import Module from "@robinpath/form";

const rp = new RobinPath();
rp.registerModule(Module.name, Module.functions);
rp.registerModuleMeta(Module.name, Module.functionMetadata);

const result = await rp.executeScript(`
  form.textarea "bio" {"label": "Bio", "maxLength": 1000}
`);
```

## Full API Reference

See [MODULE.md](./MODULE.md) for complete documentation including all parameters, return types, error handling, and advanced examples.

## Related Modules

- [`@robinpath/formdata`](../formdata) — HTTP multipart FormData builder and file uploads (renamed from the old `form` module)
- [`@robinpath/validate`](../validate) — Additional validation utilities
- [`@robinpath/schema`](../schema) — JSON schema validation
- [`@robinpath/hubspot`](../hubspot) — CRM integration for lead capture forms
- [`@robinpath/slack`](../slack) — Team notifications from form submissions
- [`@robinpath/shopify`](../shopify) — E-commerce product creation from forms

## License

MIT
