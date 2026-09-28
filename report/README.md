<!-- kiro-classification: public -->

# Comparison_Report

The Comparison_Report, its derived Public_Variant, and the two machine-readable Cost_Model
files: `cost-model.json` classified `public` and `cost-model.confidential.json` carrying the
line items whose pricing is available only from confidential material. Written by their own
tasks.

`cost-model.schema.json` constrains both of those files and is checked by
`tests/test_cost_model_schema.py` in the offline suite. It holds no figures: which citation
form a line item must carry follows from the document's classification, so the split between
the two files is mechanical rather than editorial.
