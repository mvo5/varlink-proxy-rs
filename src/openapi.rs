use serde_json::{Value, json};
use varlink_parser::{IDL, VEnum, VStruct, VStructOrEnum, VType, VTypeExt};

fn vtype_ext_to_schema(vtype: &VTypeExt) -> Value {
    match vtype {
        VTypeExt::Plain(vtype) => match vtype {
            VType::Bool => json!({"type": "boolean"}),
            VType::Int => json!({"type": "integer"}),
            VType::Float => json!({"type": "number"}),
            VType::String => json!({"type": "string"}),
            VType::Object => json!({"type": "object"}),
            VType::Typename(name) => {
                json!({"$ref": format!("#/components/schemas/{name}")})
            }
            VType::Struct(s) => vstruct_to_schema(s),
            VType::Enum(e) => venum_to_schema(e),
        },
        VTypeExt::Array(inner) => {
            json!({"type": "array", "items": vtype_ext_to_schema(inner)})
        }
        VTypeExt::Dict(inner) => {
            json!({"type": "object", "additionalProperties": vtype_ext_to_schema(inner)})
        }
        VTypeExt::Option(inner) => vtype_ext_to_schema(inner),
    }
}

fn vstruct_to_schema(vstruct: &VStruct) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    for arg in &vstruct.elts {
        properties.insert(arg.name.to_string(), vtype_ext_to_schema(&arg.vtype));
        if !matches!(arg.vtype, VTypeExt::Option(_)) {
            required.push(Value::String(arg.name.to_string()));
        }
    }

    let mut schema = serde_json::Map::new();
    schema.insert("type".to_string(), json!("object"));
    schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert("required".to_string(), Value::Array(required));
    }
    Value::Object(schema)
}

fn venum_to_schema(venum: &VEnum) -> Value {
    json!({
        "type": "string",
        "enum": venum.elts,
    })
}

pub fn idl_to_openapi(address: &str, iface: &IDL) -> Value {
    let mut paths = serde_json::Map::new();

    for &method_name in &iface.method_keys {
        let method = &iface.methods[method_name];
        let full_method = format!("{}.{}", iface.name, method_name);
        let path = format!("/call/{address}/{full_method}");

        let mut operation = serde_json::Map::new();
        operation.insert("operationId".to_string(), json!(method_name));
        if !method.doc.is_empty() {
            operation.insert("description".to_string(), json!(method.doc));
        }
        operation.insert(
            "requestBody".to_string(),
            json!({
                "required": true,
                "content": {
                    "application/json": {
                        "schema": vstruct_to_schema(&method.input)
                    }
                }
            }),
        );
        operation.insert(
            "responses".to_string(),
            json!({
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": vstruct_to_schema(&method.output)
                        }
                    }
                }
            }),
        );

        let path_item = json!({ "post": Value::Object(operation) });
        paths.insert(path, path_item);
    }

    let mut schemas = serde_json::Map::new();

    for &typedef_name in &iface.typedef_keys {
        let typedef = &iface.typedefs[typedef_name];
        let mut schema = match &typedef.elt {
            VStructOrEnum::VStruct(s) => vstruct_to_schema(s),
            VStructOrEnum::VEnum(e) => venum_to_schema(e),
        };
        if !typedef.doc.is_empty() {
            schema
                .as_object_mut()
                .unwrap()
                .insert("description".to_string(), json!(typedef.doc));
        }
        schemas.insert(typedef_name.to_string(), schema);
    }

    for &error_name in &iface.error_keys {
        let error = &iface.errors[error_name];
        let mut schema = vstruct_to_schema(&error.parm);
        if !error.doc.is_empty() {
            schema
                .as_object_mut()
                .unwrap()
                .insert("description".to_string(), json!(error.doc));
        }
        schemas.insert(error_name.to_string(), schema);
    }

    let mut info = serde_json::Map::new();
    info.insert("title".to_string(), json!(iface.name));
    if !iface.doc.is_empty() {
        info.insert("description".to_string(), json!(iface.doc));
    }

    let mut doc = serde_json::Map::new();
    doc.insert("openapi".to_string(), json!("3.1.0"));
    doc.insert("info".to_string(), Value::Object(info));
    doc.insert("paths".to_string(), Value::Object(paths));
    if !schemas.is_empty() {
        doc.insert(
            "components".to_string(),
            json!({ "schemas": Value::Object(schemas) }),
        );
    }

    Value::Object(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A varlink IDL that exercises all type features: methods with typed
    // input/output, a struct typedef, an enum typedef, an error with
    // parameters, arrays, dicts, optionals, and doc strings.
    const TEST_IDL: &str = "\
# A test interface
interface com.example.test

# Status values
type Status (enabled: bool, tag: ?string)

# Priority levels
type Priority (low, medium, high)

# Item not found
error ItemNotFound (id: int)

# Get an item by id
method GetItem(id: int, options: ?object) -> (
  name: string,
  score: float,
  status: Status,
  tags: []string,
  metadata: [string]int
)
";

    #[test]
    fn test_idl_to_openapi() {
        let iface = IDL::try_from(TEST_IDL).expect("failed to parse test IDL");
        let doc = idl_to_openapi("com.example.test", &iface);

        // top-level structure
        assert_eq!(doc["openapi"], "3.1.0");
        assert_eq!(doc["info"]["title"], "com.example.test");
        assert_eq!(doc["info"]["description"], "A test interface");

        // paths - one POST for GetItem
        let path = &doc["paths"]["/call/com.example.test/com.example.test.GetItem"];
        assert!(path.is_object(), "missing path for GetItem");
        let post = &path["post"];
        assert_eq!(post["operationId"], "GetItem");
        assert_eq!(post["description"], "Get an item by id");

        // request body schema
        let req_schema =
            &post["requestBody"]["content"]["application/json"]["schema"];
        assert_eq!(req_schema["type"], "object");
        assert_eq!(req_schema["properties"]["id"]["type"], "integer");
        assert_eq!(req_schema["properties"]["options"]["type"], "object");
        // "id" is required, "options" is optional
        let required: Vec<&str> = req_schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(required.contains(&"id"));
        assert!(!required.contains(&"options"));

        // response schema
        let resp_schema =
            &post["responses"]["200"]["content"]["application/json"]["schema"];
        assert_eq!(resp_schema["properties"]["name"]["type"], "string");
        assert_eq!(resp_schema["properties"]["score"]["type"], "number");
        assert_eq!(
            resp_schema["properties"]["status"]["$ref"],
            "#/components/schemas/Status"
        );
        // array type
        assert_eq!(resp_schema["properties"]["tags"]["type"], "array");
        assert_eq!(resp_schema["properties"]["tags"]["items"]["type"], "string");
        // dict type
        assert_eq!(resp_schema["properties"]["metadata"]["type"], "object");
        assert_eq!(
            resp_schema["properties"]["metadata"]["additionalProperties"]["type"],
            "integer"
        );

        // components/schemas - struct typedef
        let status_schema = &doc["components"]["schemas"]["Status"];
        assert_eq!(status_schema["type"], "object");
        assert_eq!(status_schema["description"], "Status values");
        assert_eq!(status_schema["properties"]["enabled"]["type"], "boolean");
        assert_eq!(status_schema["properties"]["tag"]["type"], "string");
        // "enabled" required, "tag" optional
        let status_required: Vec<&str> = status_schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(status_required.contains(&"enabled"));
        assert!(!status_required.contains(&"tag"));

        // components/schemas - enum typedef
        let priority_schema = &doc["components"]["schemas"]["Priority"];
        assert_eq!(priority_schema["type"], "string");
        assert_eq!(priority_schema["description"], "Priority levels");
        assert_eq!(
            priority_schema["enum"],
            json!(["low", "medium", "high"])
        );

        // components/schemas - error
        let error_schema = &doc["components"]["schemas"]["ItemNotFound"];
        assert_eq!(error_schema["type"], "object");
        assert_eq!(error_schema["description"], "Item not found");
        assert_eq!(error_schema["properties"]["id"]["type"], "integer");
    }
}
