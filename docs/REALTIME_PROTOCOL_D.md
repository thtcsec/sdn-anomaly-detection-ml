# Protocol D: realtime, scenario-held-out evaluation

This protocol measures the candidate controller at the point where it can make
a decision. It does not add data and does not modify labels.

- Source: `dataset/flow_stats_grouped.csv`, only real rows with known
  `run_id` and `scenario_id`.
- Split: Leave-One-Scenario-Out. Every repeat of a scenario remains in the
  outer test fold together.
- Features: the eight OpenFlow counter/rate fields after excluding raw
  `tp_src` and `tp_dst`.
- Samples: only the first three polls of each 5-tuple; no final-flow state is
  available to the model.
- Training: no SMOTE. Scaler is fit only on the outer-train fold.
- Alert endpoint: a source must be anomalous in three consecutive controller
  polling rounds. Attack episodes report detection rate and time to alert;
  Normal episodes report false-alert rate.

Run the evaluator before training the candidate artifact:

```powershell
python src/eval_realtime_scenario_held_out.py
python src/train_realtime_robust.py
```

`train_realtime_robust.py` writes a separately named model and never overwrites
the currently deployed legacy model. The model is activated only by explicitly
setting `selected_model` to `xgboost_robust` in `dataset/controller_config.json`.

The valid headline is the scenario-held-out episode result, including failed
scenarios. Random-flow accuracy and grouped-by-run accuracy remain historical
or intermediate diagnostics, not generalization claims.
