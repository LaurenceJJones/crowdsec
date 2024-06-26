// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
)

// DecisionUpdate is the builder for updating Decision entities.
type DecisionUpdate struct {
	config
	hooks    []Hook
	mutation *DecisionMutation
}

// Where appends a list predicates to the DecisionUpdate builder.
func (du *DecisionUpdate) Where(ps ...predicate.Decision) *DecisionUpdate {
	du.mutation.Where(ps...)
	return du
}

// SetUpdatedAt sets the "updated_at" field.
func (du *DecisionUpdate) SetUpdatedAt(t time.Time) *DecisionUpdate {
	du.mutation.SetUpdatedAt(t)
	return du
}

// SetUntil sets the "until" field.
func (du *DecisionUpdate) SetUntil(t time.Time) *DecisionUpdate {
	du.mutation.SetUntil(t)
	return du
}

// SetNillableUntil sets the "until" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableUntil(t *time.Time) *DecisionUpdate {
	if t != nil {
		du.SetUntil(*t)
	}
	return du
}

// ClearUntil clears the value of the "until" field.
func (du *DecisionUpdate) ClearUntil() *DecisionUpdate {
	du.mutation.ClearUntil()
	return du
}

// SetAlertDecisions sets the "alert_decisions" field.
func (du *DecisionUpdate) SetAlertDecisions(i int) *DecisionUpdate {
	du.mutation.SetAlertDecisions(i)
	return du
}

// SetNillableAlertDecisions sets the "alert_decisions" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableAlertDecisions(i *int) *DecisionUpdate {
	if i != nil {
		du.SetAlertDecisions(*i)
	}
	return du
}

// ClearAlertDecisions clears the value of the "alert_decisions" field.
func (du *DecisionUpdate) ClearAlertDecisions() *DecisionUpdate {
	du.mutation.ClearAlertDecisions()
	return du
}

// SetOwnerID sets the "owner" edge to the Alert entity by ID.
func (du *DecisionUpdate) SetOwnerID(id int) *DecisionUpdate {
	du.mutation.SetOwnerID(id)
	return du
}

// SetNillableOwnerID sets the "owner" edge to the Alert entity by ID if the given value is not nil.
func (du *DecisionUpdate) SetNillableOwnerID(id *int) *DecisionUpdate {
	if id != nil {
		du = du.SetOwnerID(*id)
	}
	return du
}

// SetOwner sets the "owner" edge to the Alert entity.
func (du *DecisionUpdate) SetOwner(a *Alert) *DecisionUpdate {
	return du.SetOwnerID(a.ID)
}

// Mutation returns the DecisionMutation object of the builder.
func (du *DecisionUpdate) Mutation() *DecisionMutation {
	return du.mutation
}

// ClearOwner clears the "owner" edge to the Alert entity.
func (du *DecisionUpdate) ClearOwner() *DecisionUpdate {
	du.mutation.ClearOwner()
	return du
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (du *DecisionUpdate) Save(ctx context.Context) (int, error) {
	du.defaults()
	return withHooks(ctx, du.sqlSave, du.mutation, du.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (du *DecisionUpdate) SaveX(ctx context.Context) int {
	affected, err := du.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (du *DecisionUpdate) Exec(ctx context.Context) error {
	_, err := du.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (du *DecisionUpdate) ExecX(ctx context.Context) {
	if err := du.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (du *DecisionUpdate) defaults() {
	if _, ok := du.mutation.UpdatedAt(); !ok {
		v := decision.UpdateDefaultUpdatedAt()
		du.mutation.SetUpdatedAt(v)
	}
}

func (du *DecisionUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(decision.Table, decision.Columns, sqlgraph.NewFieldSpec(decision.FieldID, field.TypeInt))
	if ps := du.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := du.mutation.UpdatedAt(); ok {
		_spec.SetField(decision.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := du.mutation.Until(); ok {
		_spec.SetField(decision.FieldUntil, field.TypeTime, value)
	}
	if du.mutation.UntilCleared() {
		_spec.ClearField(decision.FieldUntil, field.TypeTime)
	}
	if du.mutation.StartIPCleared() {
		_spec.ClearField(decision.FieldStartIP, field.TypeInt64)
	}
	if du.mutation.EndIPCleared() {
		_spec.ClearField(decision.FieldEndIP, field.TypeInt64)
	}
	if du.mutation.StartSuffixCleared() {
		_spec.ClearField(decision.FieldStartSuffix, field.TypeInt64)
	}
	if du.mutation.EndSuffixCleared() {
		_spec.ClearField(decision.FieldEndSuffix, field.TypeInt64)
	}
	if du.mutation.IPSizeCleared() {
		_spec.ClearField(decision.FieldIPSize, field.TypeInt64)
	}
	if du.mutation.UUIDCleared() {
		_spec.ClearField(decision.FieldUUID, field.TypeString)
	}
	if du.mutation.OwnerCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := du.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, du.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{decision.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	du.mutation.done = true
	return n, nil
}

// DecisionUpdateOne is the builder for updating a single Decision entity.
type DecisionUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *DecisionMutation
}

// SetUpdatedAt sets the "updated_at" field.
func (duo *DecisionUpdateOne) SetUpdatedAt(t time.Time) *DecisionUpdateOne {
	duo.mutation.SetUpdatedAt(t)
	return duo
}

// SetUntil sets the "until" field.
func (duo *DecisionUpdateOne) SetUntil(t time.Time) *DecisionUpdateOne {
	duo.mutation.SetUntil(t)
	return duo
}

// SetNillableUntil sets the "until" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableUntil(t *time.Time) *DecisionUpdateOne {
	if t != nil {
		duo.SetUntil(*t)
	}
	return duo
}

// ClearUntil clears the value of the "until" field.
func (duo *DecisionUpdateOne) ClearUntil() *DecisionUpdateOne {
	duo.mutation.ClearUntil()
	return duo
}

// SetAlertDecisions sets the "alert_decisions" field.
func (duo *DecisionUpdateOne) SetAlertDecisions(i int) *DecisionUpdateOne {
	duo.mutation.SetAlertDecisions(i)
	return duo
}

// SetNillableAlertDecisions sets the "alert_decisions" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableAlertDecisions(i *int) *DecisionUpdateOne {
	if i != nil {
		duo.SetAlertDecisions(*i)
	}
	return duo
}

// ClearAlertDecisions clears the value of the "alert_decisions" field.
func (duo *DecisionUpdateOne) ClearAlertDecisions() *DecisionUpdateOne {
	duo.mutation.ClearAlertDecisions()
	return duo
}

// SetOwnerID sets the "owner" edge to the Alert entity by ID.
func (duo *DecisionUpdateOne) SetOwnerID(id int) *DecisionUpdateOne {
	duo.mutation.SetOwnerID(id)
	return duo
}

// SetNillableOwnerID sets the "owner" edge to the Alert entity by ID if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableOwnerID(id *int) *DecisionUpdateOne {
	if id != nil {
		duo = duo.SetOwnerID(*id)
	}
	return duo
}

// SetOwner sets the "owner" edge to the Alert entity.
func (duo *DecisionUpdateOne) SetOwner(a *Alert) *DecisionUpdateOne {
	return duo.SetOwnerID(a.ID)
}

// Mutation returns the DecisionMutation object of the builder.
func (duo *DecisionUpdateOne) Mutation() *DecisionMutation {
	return duo.mutation
}

// ClearOwner clears the "owner" edge to the Alert entity.
func (duo *DecisionUpdateOne) ClearOwner() *DecisionUpdateOne {
	duo.mutation.ClearOwner()
	return duo
}

// Where appends a list predicates to the DecisionUpdate builder.
func (duo *DecisionUpdateOne) Where(ps ...predicate.Decision) *DecisionUpdateOne {
	duo.mutation.Where(ps...)
	return duo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (duo *DecisionUpdateOne) Select(field string, fields ...string) *DecisionUpdateOne {
	duo.fields = append([]string{field}, fields...)
	return duo
}

// Save executes the query and returns the updated Decision entity.
func (duo *DecisionUpdateOne) Save(ctx context.Context) (*Decision, error) {
	duo.defaults()
	return withHooks(ctx, duo.sqlSave, duo.mutation, duo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (duo *DecisionUpdateOne) SaveX(ctx context.Context) *Decision {
	node, err := duo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (duo *DecisionUpdateOne) Exec(ctx context.Context) error {
	_, err := duo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (duo *DecisionUpdateOne) ExecX(ctx context.Context) {
	if err := duo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (duo *DecisionUpdateOne) defaults() {
	if _, ok := duo.mutation.UpdatedAt(); !ok {
		v := decision.UpdateDefaultUpdatedAt()
		duo.mutation.SetUpdatedAt(v)
	}
}

func (duo *DecisionUpdateOne) sqlSave(ctx context.Context) (_node *Decision, err error) {
	_spec := sqlgraph.NewUpdateSpec(decision.Table, decision.Columns, sqlgraph.NewFieldSpec(decision.FieldID, field.TypeInt))
	id, ok := duo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Decision.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := duo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, decision.FieldID)
		for _, f := range fields {
			if !decision.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != decision.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := duo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := duo.mutation.UpdatedAt(); ok {
		_spec.SetField(decision.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := duo.mutation.Until(); ok {
		_spec.SetField(decision.FieldUntil, field.TypeTime, value)
	}
	if duo.mutation.UntilCleared() {
		_spec.ClearField(decision.FieldUntil, field.TypeTime)
	}
	if duo.mutation.StartIPCleared() {
		_spec.ClearField(decision.FieldStartIP, field.TypeInt64)
	}
	if duo.mutation.EndIPCleared() {
		_spec.ClearField(decision.FieldEndIP, field.TypeInt64)
	}
	if duo.mutation.StartSuffixCleared() {
		_spec.ClearField(decision.FieldStartSuffix, field.TypeInt64)
	}
	if duo.mutation.EndSuffixCleared() {
		_spec.ClearField(decision.FieldEndSuffix, field.TypeInt64)
	}
	if duo.mutation.IPSizeCleared() {
		_spec.ClearField(decision.FieldIPSize, field.TypeInt64)
	}
	if duo.mutation.UUIDCleared() {
		_spec.ClearField(decision.FieldUUID, field.TypeString)
	}
	if duo.mutation.OwnerCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := duo.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &Decision{config: duo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, duo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{decision.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	duo.mutation.done = true
	return _node, nil
}
