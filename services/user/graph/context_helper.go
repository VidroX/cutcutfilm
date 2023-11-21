package graph

import (
	"context"
	"log"

	"github.com/VidroX/cutcutfilm-shared/translator"
)

func GetLocalizer(ctx context.Context) *translator.NebulaLocalizer {
	contextTranslator := ctx.Value(translator.Key).(*translator.NebulaLocalizer)

	if contextTranslator == nil {
		log.Panic("Could not retrieve translator")
		return nil
	}

	return contextTranslator
}
